using System.IO.Hashing;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Gallery;

/// <summary>
/// Writes each distinct image once into the report's image folder, named by its content hash.
/// Uses CreateNew so a pre-planted file is never trusted or overwritten.
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
        var name = $"{XxHash64.HashToUInt64(image):x16}.{extension}";
        if (_written.Add(name))
        {
            Directory.CreateDirectory(Folder);
            using var fs = new FileStream(Path.Combine(Folder, name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            fs.Write(image);
            FilesWritten++;
            BytesWritten += image.Length;
        }
        return name;
    }

    public static string Extension(ImageFormat f) => f switch
    {
        ImageFormat.Jpeg => "jpg", ImageFormat.Png => "png", ImageFormat.Bmp => "bmp", _ => "bin",
    };

    /// <summary>Extension from image magic bytes (for sources that don't use the thumbcache format enum).</summary>
    public static string ExtensionFor(ReadOnlySpan<byte> bytes) => bytes switch
    {
        [0xFF, 0xD8, 0xFF, ..] => "jpg",
        [0x89, 0x50, 0x4E, 0x47, ..] => "png",
        [0x47, 0x49, 0x46, 0x38, ..] => "gif",
        [0x52, 0x49, 0x46, 0x46, _, _, _, _, 0x57, 0x45, 0x42, 0x50, ..] => "webp",
        [0x42, 0x4D, ..] => "bmp",
        [0x00, 0x00, 0x01, 0x00, ..] => "ico",
        [_, _, _, _, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66, ..] => "avif",   // ....ftypavif
        _ when LooksLikeSvg(bytes) => "svg",
        _ => "bin",
    };

    static bool LooksLikeSvg(ReadOnlySpan<byte> bytes)
    {
        var head = System.Text.Encoding.UTF8.GetString(bytes[..Math.Min(bytes.Length, 512)]).TrimStart('﻿', ' ', '\r', '\n', '\t');
        return head.StartsWith("<svg", StringComparison.OrdinalIgnoreCase)
            || (head.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) && head.Contains("<svg", StringComparison.OrdinalIgnoreCase));
    }
}
