using System.IO.Hashing;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Gallery;

/// <summary>
/// Writes each distinct image once into the report's image folder (in a subfolder by hash prefix), named by its content hash.
/// Uses CreateNew so a pre-planted file is never overwritten; an existing file under the same name is accepted only
/// when its bytes are identical (then the picture is already stored). One store is shared by every source of a run.
/// </summary>
public sealed class ImageStore(string folder)
{
    readonly HashSet<string> _written = new(StringComparer.OrdinalIgnoreCase);
    public string Folder { get; } = folder;
    public int FilesWritten { get; private set; }
    public long BytesWritten { get; private set; }

    public string Save(ReadOnlySpan<byte> image, ImageFormat format) => Save(image, Extension(format));

    public string Save(ReadOnlySpan<byte> image, string extension)
    {
        // In one of 256 subfolders by hash prefix: a FAT32 folder holds only about 21,800 such names.
        var hash = $"{XxHash64.HashToUInt64(image):x16}";
        var name = $"{hash[..2]}/{hash}.{extension}";
        if (_written.Contains(name)) return name;
        var path = Path.Combine(Folder, hash[..2], $"{hash}.{extension}");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            fs.Write(image);
            FilesWritten++;
            BytesWritten += image.Length;
        }
        catch (IOException) when (File.Exists(path))
        {
            if (!SameContent(path, image)) throw new IOException($"{name} already exists in the picture folder with different content; it was not trusted.");
        }
        _written.Add(name);
        return name;
    }

    static bool SameContent(string path, ReadOnlySpan<byte> image)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (fs.Length != image.Length) return false;
        var existing = new byte[image.Length];
        fs.ReadExactly(existing);
        return image.SequenceEqual(existing);
    }

    public static string Extension(ImageFormat f) => f switch
    {
        ImageFormat.Jpeg => "jpg", ImageFormat.Png => "png", ImageFormat.Bmp => "bmp", _ => "bin",
    };

    /// <summary>
    /// Extension from image magic bytes (for sources that don't use the thumbcache format enum). Anything else, SVG
    /// included, is saved as .bin: an SVG is a document that can run script when opened from the report folder.
    /// </summary>
    public static string ExtensionFor(ReadOnlySpan<byte> bytes) => bytes switch
    {
        [0xFF, 0xD8, 0xFF, ..] => "jpg",
        [0x89, 0x50, 0x4E, 0x47, ..] => "png",
        [0x47, 0x49, 0x46, 0x38, ..] => "gif",
        [0x52, 0x49, 0x46, 0x46, _, _, _, _, 0x57, 0x45, 0x42, 0x50, ..] => "webp",
        [0x42, 0x4D, ..] => "bmp",
        [0x00, 0x00, 0x01, 0x00, ..] => "ico",
        [_, _, _, _, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66, ..] => "avif",   // ....ftypavif
        _ => "bin",
    };
}
