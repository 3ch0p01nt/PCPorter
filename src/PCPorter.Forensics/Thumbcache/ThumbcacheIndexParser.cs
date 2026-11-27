using System.Buffers.Binary;

namespace PCPorter.Forensics.Thumbcache;

/// <summary>
/// Reads the cache ids listed in thumbcache_idx.db (signature "IMMM"). Layout verified on Windows 11 26200
/// (version 0x20): signature at byte 4, 72-byte records from offset 72, record starts with the 8-byte cache id
/// (1,032 of 1,040 known ids found). Other versions return null (unsupported, not an error).
/// An entry present in a cache file but not listed here is stale: Windows no longer points to it.
/// </summary>
public static class ThumbcacheIndexParser
{
    const int RecordSize = 72, FirstRecord = 72;
    static ReadOnlySpan<byte> Signature => "IMMM"u8;

    public static HashSet<ulong>? ReadIds(Stream s)
    {
        var header = new byte[FirstRecord];
        if (Read(s, 0, header) < 16) return null;
        int sig = header.AsSpan(0, 4).SequenceEqual(Signature) ? 0 : header.AsSpan(4, 4).SequenceEqual(Signature) ? 4 : -1;
        if (sig < 0) return null;
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(sig + 4));
        if (version != 0x20) return null;

        var ids = new HashSet<ulong>();
        var rec = new byte[RecordSize];
        for (long pos = FirstRecord; pos + RecordSize <= s.Length; pos += RecordSize)
        {
            Read(s, pos, rec);
            var id = BinaryPrimitives.ReadUInt64LittleEndian(rec);
            if (id != 0) ids.Add(id);
        }
        return ids;
    }

    public static HashSet<ulong>? ReadIds(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return ReadIds(fs);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    static int Read(Stream s, long pos, byte[] buf)
    {
        s.Position = pos;
        int total = 0;
        while (total < buf.Length) { int n = s.Read(buf, total, buf.Length - total); if (n == 0) break; total += n; }
        return total;
    }
}
