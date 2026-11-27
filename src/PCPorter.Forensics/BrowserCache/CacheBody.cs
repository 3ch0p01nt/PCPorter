using System.IO.Compression;
using Microsoft.Win32.SafeHandles;

namespace PCPorter.Forensics.BrowserCache;

/// <summary>Shared helpers for browser cache sources: read-only file access, HTTP header parsing, body decoding, image sniffing.</summary>
internal static class CacheBody
{
    public const int MinBodyBytes = 64;
    public const int MaxBodyBytes = 20 * 1024 * 1024;

    /// <summary>Opens a file for reading without blocking the browser that holds it open.</summary>
    public static SafeFileHandle OpenShared(string path) =>
        File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>Reads up to <paramref name="count"/> bytes at <paramref name="offset"/>; returns fewer at end of file.</summary>
    public static byte[] ReadAt(SafeFileHandle handle, long offset, int count)
    {
        if (offset < 0 || count <= 0) return [];
        long length = RandomAccess.GetLength(handle);
        if (offset >= length) return [];
        count = (int)Math.Min(count, length - offset);
        var buffer = new byte[count];
        int total = 0;
        while (total < count)
        {
            int n = RandomAccess.Read(handle, buffer.AsSpan(total), offset + total);
            if (n <= 0) break;
            total += n;
        }
        return total == count ? buffer : buffer[..total];
    }

    /// <summary>Returns the last http(s) URL in a cache key (keys may be prefixed, e.g. "1/0/_dk_https://a https://a https://b/x.png").</summary>
    public static string ExtractUrl(string key)
    {
        int i = Math.Max(key.LastIndexOf("https://", StringComparison.OrdinalIgnoreCase),
                         key.LastIndexOf("http://", StringComparison.OrdinalIgnoreCase));
        if (i < 0) return key.Trim();
        int end = key.IndexOfAny([' ', '\t', '\r', '\n', '\0'], i);
        return end < 0 ? key[i..] : key[i..end];
    }

    /// <summary>Recognises JPEG, PNG, GIF, WebP and BMP by their first bytes. Returns a content type or null.</summary>
    public static string? SniffImage(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "image/jpeg";
        if (b.Length >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47
            && b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A) return "image/png";
        if (b.Length >= 6 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8'
            && (b[4] == '7' || b[4] == '9') && b[5] == 'a') return "image/gif";
        if (b.Length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
            && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return "image/webp";
        if (b.Length >= 14 && b[0] == 'B' && b[1] == 'M') return "image/bmp";
        return null;
    }

    /// <summary>Undoes a Content-Encoding. Returns null for unsupported encodings, bad data or output over the size cap.</summary>
    public static byte[]? Decode(byte[] raw, string? contentEncoding, int maxOutput = MaxBodyBytes)
    {
        string enc = (contentEncoding ?? "").Trim().ToLowerInvariant();
        if (enc is "" or "identity" or "none") return raw;
        try
        {
            using var input = new MemoryStream(raw, writable: false);
            using Stream decoder = enc switch
            {
                "gzip" or "x-gzip" => new GZipStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                "deflate" => LooksLikeZlib(raw) ? new ZLibStream(input, CompressionMode.Decompress) : new DeflateStream(input, CompressionMode.Decompress),
                _ => Stream.Null,
            };
            if (decoder == Stream.Null) return null;
            using var output = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = decoder.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, n);
                if (output.Length > maxOutput) return null;
            }
            return output.ToArray();
        }
        catch (InvalidDataException) { return null; }
        catch (IOException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    private static bool LooksLikeZlib(byte[] b) =>
        b.Length >= 2 && (b[0] & 0x0F) == 8 && ((b[0] << 8) | b[1]) % 31 == 0;

    /// <summary>Parsed HTTP response headers.</summary>
    public sealed record HttpHead(int? Status, string? ContentType, string? ContentEncoding, string? Date)
    {
        public static readonly HttpHead Empty = new(null, null, null, null);

        /// <summary>Media type without parameters, lower case (e.g. "image/png"), or null.</summary>
        public string? MediaType
        {
            get
            {
                if (string.IsNullOrWhiteSpace(ContentType)) return null;
                int semi = ContentType.IndexOf(';');
                return (semi < 0 ? ContentType : ContentType[..semi]).Trim().ToLowerInvariant();
            }
        }
    }

    /// <summary>Parses header lines (status line first). Lines may be separated by NUL (Chromium) or CRLF (Firefox).</summary>
    public static HttpHead ParseHead(IEnumerable<string> lines)
    {
        int? status = null;
        string? type = null, encoding = null, date = null;
        bool first = true;
        foreach (var raw in lines)
        {
            string line = raw.Trim();
            if (first)
            {
                first = false;
                if (line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int s)) status = s;
                    continue;
                }
            }
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string name = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();
            if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) type ??= value;
            else if (name.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase)) encoding ??= value;
            else if (name.Equals("Date", StringComparison.OrdinalIgnoreCase)) date ??= value;
        }
        return new HttpHead(status, type, encoding, date);
    }

    /// <summary>
    /// Decides whether a cached body is an image and returns its decoded bytes and content type.
    /// <paramref name="readBody"/> is only called when needed; <paramref name="peek"/> returns the first bytes of the raw body.
    /// </summary>
    public static (byte[] Bytes, string ContentType)? TryGetImage(
        HttpHead head, long rawSize, Func<int, byte[]?> peek, Func<byte[]?> readBody)
    {
        if (rawSize <= 0 || rawSize > MaxBodyBytes) return null; // the 64-byte minimum applies to the decoded body
        string? media = head.MediaType;
        bool declaredImage = media is not null && media.StartsWith("image/", StringComparison.Ordinal);
        string enc = (head.ContentEncoding ?? "").Trim().ToLowerInvariant();
        bool encoded = enc is not ("" or "identity" or "none");

        if (!declaredImage && !encoded)
        {
            // Cheap check before reading the whole body.
            var prefix = peek(16);
            if (prefix is null || SniffImage(prefix) is null) return null;
        }

        var raw = readBody();
        if (raw is null || raw.Length == 0) return null;
        var body = Decode(raw, head.ContentEncoding);
        if (body is null && encoded && SniffImage(raw) is not null) body = raw; // mislabelled encoding
        if (body is null || body.Length < MinBodyBytes || body.Length > MaxBodyBytes) return null;

        string? sniffed = SniffImage(body);
        if (!declaredImage && sniffed is null) return null;
        return (body, declaredImage ? media! : sniffed!);
    }

    public static DateTimeOffset? FromWindowsMicroseconds(long us)
    {
        // Valid range roughly 1970..2200 to reject garbage.
        const long min = 11_644_473_600_000_000L;   // 1970-01-01
        const long max = 18_946_684_800_000_000L;   // ~2201
        if (us < min || us > max) return null;
        return new DateTimeOffset(DateTime.FromFileTimeUtc(us * 10));
    }

    public static DateTimeOffset? FromUnixSeconds(uint seconds) =>
        seconds is 0 or uint.MaxValue ? null : DateTimeOffset.FromUnixTimeSeconds(seconds);

    public static DateTimeOffset? SafeFileTime(Func<DateTime> get)
    {
        try
        {
            var t = get();
            return t.Year <= 1601 ? null : new DateTimeOffset(DateTime.SpecifyKind(t, DateTimeKind.Utc));
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
