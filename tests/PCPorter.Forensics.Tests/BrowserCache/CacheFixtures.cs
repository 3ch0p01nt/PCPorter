using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace PCPorter.Forensics.Tests.BrowserCache;

/// <summary>Synthetic bodies and helpers shared by the browser cache tests.</summary>
internal static class Fixture
{
    public static byte[] Png(int size = 200, byte fill = 7)
    {
        var b = new byte[size];
        Array.Fill(b, fill);
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(b, 0);
        return b;
    }

    public static byte[] Jpeg(int size = 300)
    {
        var b = new byte[size];
        for (int i = 0; i < size; i++) b[i] = (byte)(i * 31);
        b[0] = 0xFF; b[1] = 0xD8; b[2] = 0xFF; b[3] = 0xE0;
        return b;
    }

    public static byte[] Html() => Encoding.ASCII.GetBytes("<!doctype html><html><body>" + new string('x', 200) + "</body></html>");

    public static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true)) gz.Write(data);
        return ms.ToArray();
    }

    public static byte[] Brotli(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var br = new BrotliStream(ms, CompressionLevel.Optimal, leaveOpen: true)) br.Write(data);
        return ms.ToArray();
    }

    public static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pcporter-cache-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static long WindowsMicros(DateTimeOffset t) => t.UtcDateTime.ToFileTimeUtc() / 10;
}

/// <summary>Writes a minimal Chromium blockfile cache: index, data_0 (rankings), data_1..data_3, f_XXXXXX.</summary>
internal sealed class BlockfileBuilder
{
    private const int TableLen = 0x100;
    private static readonly int[] BlockSizes = [36, 256, 1024, 4096];

    private readonly List<byte>[] _files = [[], [], [], []];
    private readonly Dictionary<int, byte[]> _external = [];
    private readonly List<(uint Addr, int Bucket)> _entries = [];
    private int _nextExternal = 1;

    public sealed record Entry(
        string Key, byte[] Body, string[] Headers, DateTimeOffset Created, DateTimeOffset LastUsed, bool ForceExternal = false);

    public BlockfileBuilder Add(string key, byte[] body, string contentType, DateTimeOffset created, DateTimeOffset lastUsed,
        string? contentEncoding = null, bool forceExternal = false, int status = 200)
    {
        var headers = new List<string> { $"HTTP/1.1 {status} OK", $"Content-Type: {contentType}", "Date: Tue, 24 Nov 2026 10:00:00 GMT" };
        if (contentEncoding is not null) headers.Add($"Content-Encoding: {contentEncoding}");
        return Add(new Entry(key, body, [.. headers], created, lastUsed, forceExternal));
    }

    public BlockfileBuilder Add(Entry e)
    {
        uint rankings = Allocate(0, new byte[36]);
        uint stream0 = Store(Pickle(e.Headers), false);
        uint stream1 = Store(e.Body, e.ForceExternal);
        var keyBytes = Encoding.UTF8.GetBytes(e.Key);

        int blocks = Math.Clamp((96 + keyBytes.Length + 1 + 255) / 256, 1, 4);
        var entry = new byte[blocks * 256];
        uint longKey = 0;
        if (96 + keyBytes.Length + 1 > entry.Length) longKey = Store([.. keyBytes, 0], false);
        else keyBytes.CopyTo(entry, 96);
        var s = entry.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s[0..], 0x12345678);
        BinaryPrimitives.WriteUInt32LittleEndian(s[8..], rankings);
        BinaryPrimitives.WriteInt64LittleEndian(s[24..], Fixture.WindowsMicros(e.Created));
        BinaryPrimitives.WriteInt32LittleEndian(s[32..], keyBytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(s[36..], longKey);
        BinaryPrimitives.WriteInt32LittleEndian(s[40..], Pickle(e.Headers).Length);
        BinaryPrimitives.WriteInt32LittleEndian(s[44..], e.Body.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(s[56..], stream0);
        BinaryPrimitives.WriteUInt32LittleEndian(s[60..], stream1);
        uint addr = Allocate(1, entry);

        // Rankings node: last_used, last_modified, next, prev, contents.
        int rankStart = (int)(rankings & 0xFFFF) * 36;
        BinaryPrimitives.WriteInt64LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_files[0]).Slice(rankStart), Fixture.WindowsMicros(e.LastUsed));
        BinaryPrimitives.WriteUInt32LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_files[0]).Slice(rankStart + 24), addr);

        _entries.Add((addr, _entries.Count % 3)); // 3 buckets so chains are exercised
        return this;
    }

    private uint Store(byte[] data, bool forceExternal)
    {
        if (!forceExternal)
        {
            for (int f = 1; f <= 3; f++)
                if (data.Length <= BlockSizes[f] * 4) return Allocate(f, data);
        }
        int n = _nextExternal++;
        _external[n] = data;
        return 0x80000000u | (uint)n;
    }

    private uint Allocate(int file, byte[] data)
    {
        int size = BlockSizes[file];
        int blocks = Math.Max(1, (data.Length + size - 1) / size);
        if (blocks > 4) throw new InvalidOperationException("too big for a block file");
        int start = _files[file].Count / size;
        _files[file].AddRange(data);
        _files[file].AddRange(new byte[blocks * size - data.Length]);
        int type = file + 1;
        return 0x80000000u | (uint)type << 28 | (uint)(blocks - 1) << 24 | (uint)file << 16 | (uint)start;
    }

    /// <summary>A pickled HttpResponseInfo: payload size, flags, request/response times, then the headers string.</summary>
    private static byte[] Pickle(string[] headers)
    {
        var text = Encoding.ASCII.GetBytes(string.Join("\0", headers) + "\0\0");
        int padded = (text.Length + 3) & ~3;
        var payload = new byte[4 + 8 + 8 + 4 + padded];
        BinaryPrimitives.WriteInt32LittleEndian(payload, 3);
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(20), text.Length);
        text.CopyTo(payload, 24);
        var result = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(result, payload.Length);
        payload.CopyTo(result, 4);
        return result;
    }

    public string Write(string cacheFolder)
    {
        Directory.CreateDirectory(cacheFolder);
        var index = new byte[368 + TableLen * 4];
        BinaryPrimitives.WriteUInt32LittleEndian(index, 0xC103CAC3);
        BinaryPrimitives.WriteUInt32LittleEndian(index.AsSpan(4), 0x30000);
        BinaryPrimitives.WriteInt32LittleEndian(index.AsSpan(8), _entries.Count);
        BinaryPrimitives.WriteInt32LittleEndian(index.AsSpan(28), TableLen);

        // Chain entries sharing a bucket through EntryStore.next (newest at the head).
        var heads = new Dictionary<int, uint>();
        foreach (var (addr, bucket) in _entries)
        {
            if (heads.TryGetValue(bucket, out uint previousHead))
            {
                int start = (int)(addr & 0xFFFF) * 256;
                BinaryPrimitives.WriteUInt32LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_files[1]).Slice(start + 4), previousHead);
            }
            heads[bucket] = addr;
        }
        foreach (var (bucket, addr) in heads)
            BinaryPrimitives.WriteUInt32LittleEndian(index.AsSpan(368 + bucket * 4), addr);
        File.WriteAllBytes(Path.Combine(cacheFolder, "index"), index);

        for (int f = 0; f < 4; f++)
        {
            var header = new byte[8192];
            BinaryPrimitives.WriteUInt32LittleEndian(header, 0xC104CAC3);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), 0x20000);
            BinaryPrimitives.WriteInt16LittleEndian(header.AsSpan(8), (short)f);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), BlockSizes[f]);
            File.WriteAllBytes(Path.Combine(cacheFolder, $"data_{f}"), [.. header, .. _files[f]]);
        }
        foreach (var (n, data) in _external)
            File.WriteAllBytes(Path.Combine(cacheFolder, $"f_{n:x6}"), data);
        return cacheFolder;
    }
}

/// <summary>Writes Chromium simple-cache "&lt;hash&gt;_0" files.</summary>
internal static class SimpleCacheBuilder
{
    public static void Write(string path, string key, byte[] body, string[] headers)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var stream0 = Encoding.ASCII.GetBytes("\0\0\0\0" + string.Join("\0", headers) + "\0\0");
        using var ms = new MemoryStream();
        var header = new byte[24];
        BinaryPrimitives.WriteUInt64LittleEndian(header, 0xfcfb6d1ba7725c30);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), (uint)keyBytes.Length);
        ms.Write(header);
        ms.Write(keyBytes);
        ms.Write(body);
        ms.Write(Eof(0, body.Length));
        ms.Write(stream0);
        ms.Write(new byte[32]); // key SHA-256
        ms.Write(Eof(2, stream0.Length));
        File.WriteAllBytes(path, ms.ToArray());
    }

    private static byte[] Eof(uint flags, int size)
    {
        var b = new byte[24];
        BinaryPrimitives.WriteUInt64LittleEndian(b, 0xf4fa6f45970d41d8);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), flags);
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(16), size);
        return b;
    }
}

/// <summary>Writes Firefox cache2 entry files.</summary>
internal static class FirefoxEntryBuilder
{
    public static void Write(string path, string key, byte[] body, string responseHead,
        uint fetchCount, DateTimeOffset lastFetched, DateTimeOffset lastModified)
    {
        using var ms = new MemoryStream();
        ms.Write(body);
        int chunks = (body.Length + 256 * 1024 - 1) / (256 * 1024);
        ms.Write(new byte[4 + chunks * 2]); // metadata hash + chunk hashes
        var keyBytes = Encoding.UTF8.GetBytes(key);
        foreach (uint v in new[] { 3u, fetchCount, (uint)lastFetched.ToUnixTimeSeconds(), (uint)lastModified.ToUnixTimeSeconds(),
                                   100u, uint.MaxValue, (uint)keyBytes.Length, 0u })
        {
            var b = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, v);
            ms.Write(b);
        }
        ms.Write(keyBytes);
        ms.WriteByte(0);
        foreach (var s in new[] { "request-method", "GET", "response-head", responseHead, "net-response-time-onstart", "50" })
        {
            ms.Write(Encoding.Latin1.GetBytes(s));
            ms.WriteByte(0);
        }
        var offset = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(offset, (uint)body.Length);
        ms.Write(offset);
        File.WriteAllBytes(path, ms.ToArray());
    }
}
