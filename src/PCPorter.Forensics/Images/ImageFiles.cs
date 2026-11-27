namespace PCPorter.Forensics.Images;

/// <summary>Small read-only helpers shared by the file-based image sources.</summary>
internal static class ImageFiles
{
    /// <summary>Files larger than this are not loaded into memory.</summary>
    public const long MaxImageBytes = 30L * 1024 * 1024;

    private static readonly Dictionary<string, string> ImageTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".jpg"] = "image/jpeg", [".jpeg"] = "image/jpeg", [".png"] = "image/png", [".gif"] = "image/gif",
        [".bmp"] = "image/bmp", [".webp"] = "image/webp", [".heic"] = "image/heic", [".heif"] = "image/heif",
        [".tif"] = "image/tiff", [".tiff"] = "image/tiff",
        [".raw"] = "image/x-raw", [".cr2"] = "image/x-canon-cr2", [".nef"] = "image/x-nikon-nef",
        [".arw"] = "image/x-sony-arw", [".dng"] = "image/x-adobe-dng",
    };

    private static readonly Dictionary<string, string> VideoTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".mp4"] = "video/mp4", [".mov"] = "video/quicktime", [".avi"] = "video/x-msvideo", [".mkv"] = "video/x-matroska",
    };

    public static bool IsImageExtension(string? path) => TryExtension(path, out var ext) && ImageTypes.ContainsKey(ext);

    public static bool IsVideoExtension(string? path) => TryExtension(path, out var ext) && VideoTypes.ContainsKey(ext);

    public static string? ContentTypeFromExtension(string? path) =>
        !TryExtension(path, out var ext) ? null
        : ImageTypes.TryGetValue(ext, out var image) ? image
        : VideoTypes.TryGetValue(ext, out var video) ? video
        : null;

    /// <summary>Content type from the first bytes of a file, or null when it is not a known picture format.</summary>
    public static string? SniffContentType(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') return "image/png";
        if (b.Length >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "image/jpeg";
        if (b.Length >= 6 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8') return "image/gif";
        if (b.Length >= 14 && b[0] == 'B' && b[1] == 'M') return "image/bmp";
        if (b.Length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
            && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return "image/webp";
        if (b.Length >= 4 && ((b[0] == 'I' && b[1] == 'I' && b[2] == 42 && b[3] == 0)
            || (b[0] == 'M' && b[1] == 'M' && b[2] == 0 && b[3] == 42))) return "image/tiff";
        if (b.Length >= 12 && b[4] == 'f' && b[5] == 't' && b[6] == 'y' && b[7] == 'p')
        {
            var brand = System.Text.Encoding.ASCII.GetString(b.Slice(8, 4));
            if (brand is "heic" or "heix" or "heim" or "heis" or "mif1" or "msf1") return "image/heic";
            if (brand is "avif") return "image/avif";
        }
        return null;
    }

    /// <summary>Opens a file read-only without blocking anyone else who has it open.</summary>
    public static FileStream OpenShared(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>Reads the first <paramref name="count"/> bytes (fewer if the file is shorter).</summary>
    public static byte[] ReadHead(string path, int count)
    {
        using var fs = OpenShared(path);
        var buffer = new byte[(int)Math.Min(count, fs.Length)];
        fs.ReadExactly(buffer);
        return buffer;
    }

    /// <summary>Reads a whole file; the caller has already checked the size limit.</summary>
    public static byte[] ReadAll(string path)
    {
        using var fs = OpenShared(path);
        var buffer = new byte[fs.Length];
        fs.ReadExactly(buffer);
        return buffer;
    }

    /// <summary>File times before 1980 are "not recorded" placeholders (0 = 1601-01-01).</summary>
    public static DateTimeOffset? Plausible(DateTimeOffset? value) =>
        value is { } v && v.UtcDateTime.Year >= 1980 ? v.ToUniversalTime() : null;

    public static DateTimeOffset? Plausible(DateTime utc) =>
        utc.Year >= 1980 ? new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)) : null;

    private static bool TryExtension(string? path, out string ext)
    {
        ext = "";
        if (string.IsNullOrEmpty(path)) return false;
        try { ext = Path.GetExtension(path); }
        catch (ArgumentException) { return false; }
        return ext.Length > 1;
    }
}
