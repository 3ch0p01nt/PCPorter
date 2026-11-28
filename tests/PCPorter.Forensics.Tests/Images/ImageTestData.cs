using System.Text;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PCPorter.Forensics.Tests.Images;

/// <summary>Synthetic pictures, profile folders and shortcut files for the Images tests.</summary>
internal static class ImageTestData
{
    public static byte[] Png(int width, int height, Func<int, int, double> grey) =>
        Encode(new PngBitmapEncoder(), width, height, grey);

    public static byte[] Jpeg(int width, int height, Func<int, int, double> grey, int quality = 85) =>
        Encode(new JpegBitmapEncoder { QualityLevel = quality }, width, height, grey);

    public static byte[] Encoded(BitmapEncoder encoder, int width, int height, Func<int, int, double> grey) =>
        Encode(encoder, width, height, grey);

    /// <summary>Smooth blobs: a "photo-like" picture.</summary>
    public static double Blobs(int x, int y, int w, int h)
    {
        double u = x / (double)w, v = y / (double)h;
        return 0.5 + 0.25 * Math.Sin(u * 7.0 + v * 2.0) + 0.2 * Math.Cos(v * 9.0 - u * 3.0);
    }

    /// <summary>A clearly different picture.</summary>
    public static double Stripes(int x, int y, int w, int h)
    {
        double u = x / (double)w, v = y / (double)h;
        return 0.5 + 0.45 * Math.Sin(u * 31.0 - v * 17.0) * Math.Cos(v * 23.0);
    }

    private static byte[] Encode(BitmapEncoder encoder, int width, int height, Func<int, int, double> grey)
    {
        var pixels = new byte[width * height];
        for (int y = 0; y < height; y++)
            for (int x = 0; x < width; x++)
                pixels[y * width + x] = (byte)Math.Clamp((int)Math.Round(grey(x, y) * 255), 0, 255);
        var source = BitmapSource.Create(width, height, 96, 96, PixelFormats.Gray8, null, pixels, width);
        encoder.Frames.Add(BitmapFrame.Create(source));
        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// A minimal valid shell link: ShellLinkHeader + LinkInfo (VolumeID + local base path) + terminal block.
    /// Built in code so no shell COM object is involved.
    /// </summary>
    public static byte[] Lnk(string localBasePath, DateTime targetCreatedUtc, DateTime targetModifiedUtc, DateTime targetAccessedUtc)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // ShellLinkHeader (76 bytes)
        w.Write(0x4C);
        w.Write(new Guid("00021401-0000-0000-C000-000000000046").ToByteArray());
        w.Write(0x00000002);                       // LinkFlags: HasLinkInfo
        w.Write(0x00000020);                       // FileAttributes: ARCHIVE
        w.Write(targetCreatedUtc.ToFileTimeUtc());
        w.Write(targetAccessedUtc.ToFileTimeUtc());
        w.Write(targetModifiedUtc.ToFileTimeUtc());
        w.Write(1234);                             // FileSize
        w.Write(0);                                // IconIndex
        w.Write(1);                                // ShowCommand: SW_SHOWNORMAL
        w.Write((short)0);                         // HotKey
        w.Write((short)0); w.Write(0); w.Write(0); // Reserved

        // LinkInfo
        var label = new byte[] { 0 };
        int volumeIdSize = 16 + label.Length;
        var basePath = Encoding.ASCII.GetBytes(localBasePath + "\0");
        var suffix = new byte[] { 0 };
        const int headerSize = 0x1C;
        int volumeIdOffset = headerSize;
        int basePathOffset = volumeIdOffset + volumeIdSize;
        int suffixOffset = basePathOffset + basePath.Length;
        int linkInfoSize = suffixOffset + suffix.Length;

        w.Write(linkInfoSize);
        w.Write(headerSize);
        w.Write(0x00000001);                       // VolumeIDAndLocalBasePath
        w.Write(volumeIdOffset);
        w.Write(basePathOffset);
        w.Write(0);                                // CommonNetworkRelativeLinkOffset
        w.Write(suffixOffset);
        // VolumeID
        w.Write(volumeIdSize);
        w.Write(3);                                // DRIVE_FIXED
        w.Write(0x12345678);                       // serial
        w.Write(0x10);                             // VolumeLabelOffset
        w.Write(label);
        w.Write(basePath);
        w.Write(suffix);

        w.Write(0);                                // TerminalBlock
        w.Flush();
        return ms.ToArray();
    }
}

/// <summary>A throw-away profile folder under %TEMP%.</summary>
internal sealed class TempProfile : IDisposable
{
    public string Folder { get; } = Path.Combine(Path.GetTempPath(), "pcporter-images-" + Guid.NewGuid().ToString("N"));

    public TempProfile() => Directory.CreateDirectory(Folder);

    public string Write(string relativePath, byte[] bytes)
    {
        var path = Path.Combine(Folder, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public string Recent => Path.Combine(Folder, "AppData", "Roaming", "Microsoft", "Windows", "Recent");

    public void Dispose()
    {
        try { Directory.Delete(Folder, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
