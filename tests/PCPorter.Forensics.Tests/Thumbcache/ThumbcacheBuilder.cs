using System.Buffers.Binary;
using System.Text;

namespace PCPorter.Forensics.Tests.Thumbcache;

/// <summary>
/// Builds synthetic thumbcache files for tests, in the layout of each Windows version:
/// 0x14 Vista, 0x15 Win7, 0x1A/0x1C/0x1E/0x1F/0x20 Win8+ (0x1C has a 28-byte file header).
/// </summary>
public sealed class ThumbcacheBuilder(uint version = 0x20)
{
    readonly MemoryStream _body = new();
    int _firstFreeOffset = -1;

    bool OffsetsAt16 => version is 0x1C or >= 0x1E;
    int FileHeaderSize => version == 0x1C ? 28 : 24;
    int EntryHeaderSize => version == 0x15 ? 48 : 56;
    (int IdLen, int Pad, int Data) Fields => version switch
    {
        0x14 => (24, 28, 32),
        _ => (16, 20, 24),
    };

    public static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];
    public static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 9, 9, 9, 9, 0xFF, 0xD9];

    public ThumbcacheBuilder Entry(ulong id, byte[] data, int width = 96, int height = 96, string? identifier = null, int extraTail = 1)
    {
        var ident = Encoding.Unicode.GetBytes(identifier ?? id.ToString("x16"));
        int size = EntryHeaderSize + ident.Length + data.Length + extraTail;
        var e = new byte[size];
        "CMMM"u8.CopyTo(e);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(4), (uint)size);
        BinaryPrimitives.WriteUInt64LittleEndian(e.AsSpan(8), id);
        var f = Fields;
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(f.IdLen), (uint)ident.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(f.Pad), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(f.Data), (uint)data.Length);
        if (version is not (0x14 or 0x15))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(28), (uint)width);
            BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(32), (uint)height);
        }
        ident.CopyTo(e, EntryHeaderSize);
        data.CopyTo(e, EntryHeaderSize + ident.Length);
        _body.Write(e);
        return this;
    }

    public ThumbcacheBuilder Garbage(int bytes, byte value = 0xAB)
    {
        _body.Write(Enumerable.Repeat(value, bytes).ToArray());
        return this;
    }

    /// <summary>Marks the current end of the body as the start of free space (later entries are outside the live chain).</summary>
    public ThumbcacheBuilder FreeSpaceStartsHere()
    {
        _firstFreeOffset = FileHeaderSize + (int)_body.Length;
        return this;
    }

    /// <summary>
    /// Writes a free-space record exactly as Windows 11 does (verified): id 0, no data, size covering
    /// <paramref name="coverBytes"/> bytes (normally the rest of the file).
    /// </summary>
    public ThumbcacheBuilder FreeSpaceRecord(int coverBytes)
    {
        FreeSpaceStartsHere();
        var e = new byte[EntryHeaderSize];
        "CMMM"u8.CopyTo(e);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(4), (uint)coverBytes);
        _body.Write(e);
        return this;
    }

    public byte[] Build()
    {
        var header = new byte[FileHeaderSize];
        "CMMM"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), version);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), 4);
        int firstFree = _firstFreeOffset < 0 ? FileHeaderSize + (int)_body.Length : _firstFreeOffset;
        int firstAt = OffsetsAt16 ? 16 : 12;
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(firstAt), (uint)FileHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(firstAt + 4), (uint)firstFree);
        return [.. header, .. _body.ToArray()];
    }
}
