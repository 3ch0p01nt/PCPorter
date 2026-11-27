using System.Buffers.Binary;
using System.Text;

namespace PCPorter.Forensics.Thumbcache;

public enum ImageFormat { Unknown, Jpeg, Png, Bmp }

/// <summary>
/// One cache entry. Entries without image data (<see cref="HasImage"/> false) still prove Windows displayed the item.
/// <see cref="FoundInFreeSpace"/> = found outside the live chain (in free space or by re-scanning past damage);
/// on its own this is not proof that the original was deleted.
/// </summary>
public sealed record ThumbcacheEntry(
    ulong CacheId, string Identifier, int Width, int Height,
    long Offset, long DataOffset, int DataLength, ImageFormat Format, bool FoundInFreeSpace)
{
    public bool HasImage => DataLength > 0;
}

public sealed record ThumbcacheFile(
    int Version, bool VersionKnown, int CacheType, IReadOnlyList<ThumbcacheEntry> Entries, IReadOnlyList<string> Warnings)
{
    public int ImageEntries => Entries.Count(e => e.HasImage);
    public int EmptyEntries => Entries.Count(e => !e.HasImage);
}

/// <summary>
/// Parses Windows Explorer thumbnail cache files (thumbcache_*.db / iconcache_*.db), Vista through Windows 11.
/// Streams the file (no whole-file buffers), never throws on damaged content (only on a wrong file signature),
/// steps over the free-space record, and re-scans past damage so orphaned entries are still found.
/// Layout facts verified on Windows 11 26200 (version 0x20); other versions per libwtcdb / Thumbcache Viewer.
/// </summary>
public static class ThumbcacheParser
{
    const int MaxIdentifierBytes = 2048;
    const int MaxImageBytes = 64 * 1024 * 1024;
    const int ScanChunk = 1024 * 1024;
    static readonly byte[] Signature = "CMMM"u8.ToArray();

    sealed record Layout(int HeaderSize, int IdLenAt, int PadAt, int DataAt, int WidthAt, int HeightAt);

    static readonly Layout Vista = new(56, 24, 28, 32, -1, -1);   // 8-byte extension before the identifier length
    static readonly Layout Win7 = new(48, 16, 20, 24, -1, -1);
    static readonly Layout Win8Plus = new(56, 16, 20, 24, 28, 32);

    /// <summary>(entry layout, first-entry offset field, first-free offset field, minimum header size).</summary>
    static (Layout Layout, int FirstAt, int FreeAt, int FileHeader, bool Known) VersionInfo(uint version) => version switch
    {
        0x14 => (Vista, 12, 16, 24, true),
        0x15 => (Win7, 12, 16, 24, true),
        0x1A => (Win8Plus, 12, 16, 24, true),
        0x1C => (Win8Plus, 16, 20, 28, true),
        0x1E or 0x1F or 0x20 => (Win8Plus, 16, 20, 24, true),
        _ => (Win8Plus, 16, 20, 24, false),
    };

    public static ThumbcacheFile Parse(ReadOnlyMemory<byte> file, string fileName)
    {
        using var ms = new MemoryStream(file.ToArray(), writable: false);
        return Parse(ms, fileName);
    }

    /// <summary>Parses a seekable stream. The stream position is changed; image bytes are read later with <see cref="ReadImage"/>.</summary>
    public static ThumbcacheFile Parse(Stream stream, string fileName, CancellationToken ct = default)
    {
        long length = stream.Length;
        var header = new byte[28];
        stream.Position = 0;
        int got = ReadAt(stream, 0, header);
        if (got < 24 || !header.AsSpan(0, 4).SequenceEqual(Signature))
            throw new InvalidDataException($"{fileName} is not a thumbnail cache file.");

        uint version = U32(header, 4);
        int cacheType = (int)U32(header, 8);
        var info = VersionInfo(version);
        var warnings = new List<string>();
        if (!info.Known) warnings.Add($"{fileName}: unknown cache format version 0x{version:x}; read as Windows 8+ layout.");

        long first = U32(header, info.FirstAt);
        long firstFree = U32(header, info.FreeAt);
        if (first < info.FileHeader || first > length)
        {
            if (length > info.FileHeader) warnings.Add($"{fileName}: first entry offset {first} is invalid; scanning from the start.");
            first = info.FileHeader;
        }
        if (firstFree <= 0 || firstFree > length) firstFree = length;

        var layout = info.Layout;
        var entries = new List<ThumbcacheEntry>();
        var buf = new byte[layout.HeaderSize];
        long pos = first;
        bool foundByScan = false;

        while (pos + layout.HeaderSize <= length)
        {
            ct.ThrowIfCancellationRequested();
            ReadAt(stream, pos, buf);
            if (!buf.AsSpan(0, 4).SequenceEqual(Signature))
            {
                long next = FindSignature(stream, pos + 1, length, ct);
                if (next < 0) break;
                pos = next;
                foundByScan = true;
                continue;
            }

            var r = ReadEntry(stream, buf, pos, length, layout, strict: foundByScan || pos >= firstFree, out var entry, out long advance);
            if (r == EntryResult.Truncated)
                warnings.Add($"{fileName}: entry at offset {pos} is cut off (the file may be damaged or still being written).");
            if (r != EntryResult.Ok)
            {
                long next = FindSignature(stream, pos + 1, length, ct);
                if (next < 0) break;
                pos = next;
                foundByScan = true;
                continue;
            }

            if (entry is not null) entries.Add(entry with { FoundInFreeSpace = foundByScan || pos >= firstFree });
            foundByScan = false;
            pos += advance;
        }

        return new ThumbcacheFile((int)version, info.Known, cacheType, entries, warnings);
    }

    /// <summary>Reads the image bytes of an entry, as stored (JPEG/PNG/BMP).</summary>
    public static byte[] ReadImage(Stream stream, ThumbcacheEntry entry)
    {
        var bytes = new byte[entry.DataLength];
        ReadAt(stream, entry.DataOffset, bytes);
        return bytes;
    }

    /// <summary>The image bytes of an entry from an in-memory copy of the file.</summary>
    public static ReadOnlyMemory<byte> ImageBytes(ReadOnlyMemory<byte> file, ThumbcacheEntry entry) =>
        file.Slice((int)entry.DataOffset, entry.DataLength);

    enum EntryResult { Ok, Invalid, Truncated }

    /// <param name="strict">For entries found by scanning or in free space: require a plausible identifier and real image data.</param>
    static EntryResult ReadEntry(Stream s, byte[] h, long pos, long length, Layout layout, bool strict,
        out ThumbcacheEntry? entry, out long advance)
    {
        entry = null;
        advance = layout.HeaderSize;
        long size = U32(h, 4);
        ulong id = BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(8));
        long idLen = U32(h, layout.IdLenAt);
        long pad = U32(h, layout.PadAt);
        long dataLen = U32(h, layout.DataAt);

        // The free-space record (and any blank slot): id 0 and no data. Step over its header only, so nothing
        // that follows it inside the file can be hidden by its (huge) size field.
        if (id == 0 && dataLen == 0) return EntryResult.Ok;

        if (size < layout.HeaderSize || idLen % 2 != 0 || idLen > MaxIdentifierBytes || pad >= Math.Max(size, 1)
            || dataLen > MaxImageBytes || layout.HeaderSize + idLen + pad + dataLen > size)
            return EntryResult.Invalid;
        if (pos + layout.HeaderSize + idLen + pad + dataLen > length) return EntryResult.Truncated;

        var idBytes = new byte[idLen];
        ReadAt(s, pos + layout.HeaderSize, idBytes);
        var identifier = Encoding.Unicode.GetString(idBytes).TrimEnd('\0');
        long dataAt = pos + layout.HeaderSize + idLen + pad;

        var format = ImageFormat.Unknown;
        if (dataLen > 0)
        {
            var magic = new byte[Math.Min(4, (int)dataLen)];
            ReadAt(s, dataAt, magic);
            format = DetectFormat(magic);
        }
        if (strict && (!PlausibleIdentifier(identifier) || (dataLen > 0 && format == ImageFormat.Unknown)))
            return EntryResult.Invalid;

        entry = new ThumbcacheEntry(
            CacheId: id, Identifier: identifier,
            Width: layout.WidthAt < 0 ? 0 : (int)Math.Min(U32(h, layout.WidthAt), int.MaxValue),
            Height: layout.HeightAt < 0 ? 0 : (int)Math.Min(U32(h, layout.HeightAt), int.MaxValue),
            Offset: pos, DataOffset: dataAt, DataLength: (int)dataLen, Format: format, FoundInFreeSpace: false);

        // Image entries: always advance by the size field (real files pad an extra byte or more).
        // Empty entries: same, unless the size field is implausibly large for an empty entry.
        long minimal = layout.HeaderSize + idLen + pad + dataLen;
        advance = dataLen == 0 && size > minimal + 64 ? minimal : size;
        if (pos + advance > length) advance = length - pos;
        return EntryResult.Ok;
    }

    static bool PlausibleIdentifier(string id) =>
        id.Length > 0 && (id.Length == 16 && id.All(Uri.IsHexDigit) || id.StartsWith("::", StringComparison.Ordinal) || id.Contains('\\') || id.Contains(':'));

    public static ImageFormat DetectFormat(ReadOnlySpan<byte> data) => data switch
    {
        [0xFF, 0xD8, 0xFF, ..] => ImageFormat.Jpeg,
        [0x89, 0x50, 0x4E, 0x47, ..] => ImageFormat.Png,
        [0x42, 0x4D, ..] => ImageFormat.Bmp,
        _ => ImageFormat.Unknown,
    };

    /// <summary>Finds the next "CMMM" at or after <paramref name="from"/>, reading in chunks.</summary>
    static long FindSignature(Stream s, long from, long length, CancellationToken ct)
    {
        var chunk = new byte[ScanChunk + 3];
        for (long at = from; at < length; at += ScanChunk)
        {
            ct.ThrowIfCancellationRequested();
            int n = ReadAt(s, at, chunk.AsSpan(0, (int)Math.Min(chunk.Length, length - at)));
            int i = chunk.AsSpan(0, n).IndexOf(Signature);
            if (i >= 0) return at + i;
            if (n < chunk.Length) break;
        }
        return -1;
    }

    static int ReadAt(Stream s, long pos, Span<byte> buffer)
    {
        s.Position = pos;
        int total = 0;
        while (total < buffer.Length)
        {
            int n = s.Read(buffer[total..]);
            if (n == 0) break;
            total += n;
        }
        buffer[total..].Clear();
        return total;
    }

    static uint U32(byte[] b, int at) => at + 4 <= b.Length ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at)) : 0;
}
