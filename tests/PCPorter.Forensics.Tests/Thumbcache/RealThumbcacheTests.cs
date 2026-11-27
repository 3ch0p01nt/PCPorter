using System.Windows.Media.Imaging;
using PCPorter.Forensics.Thumbcache;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.Thumbcache;

/// <summary>Runs only when this PC has Explorer thumbnail caches. Reads them read-only; writes nothing.</summary>
public sealed class LocalThumbcacheFactAttribute : FactAttribute
{
    public static string Folder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer");

    public LocalThumbcacheFactAttribute()
    {
        if (!Directory.Exists(Folder) || !Directory.EnumerateFiles(Folder, "thumbcache_*.db").Any())
            Skip = "No thumbnail cache on this PC.";
    }
}

public class RealThumbcacheTests(ITestOutputHelper output)
{
    [LocalThumbcacheFact, Trait("Category", "Live")]
    public void Every_image_in_this_pcs_caches_decodes()
    {
        int images = 0, empty = 0, free = 0, unknown = 0;
        foreach (var path in Directory.EnumerateFiles(LocalThumbcacheFactAttribute.Folder, "*cache_*.db"))
        {
            if (path.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) continue;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length == 0) continue;
            var file = ThumbcacheParser.Parse(fs, Path.GetFileName(path));
            Assert.True(file.VersionKnown);
            foreach (var e in file.Entries)
            {
                if (e.FoundInFreeSpace) free++;
                if (!e.HasImage) { empty++; continue; }
                images++;
                if (e.Format == ImageFormat.Unknown) { unknown++; continue; }
                using var ms = new MemoryStream(ThumbcacheParser.ReadImage(fs, e));
                var frame = BitmapDecoder.Create(ms, BitmapCreateOptions.None, BitmapCacheOption.OnLoad).Frames[0];
                Assert.True(frame.PixelWidth > 0);
            }
            output.WriteLine($"{Path.GetFileName(path)}: v0x{file.Version:x} {file.ImageEntries} images, {file.EmptyEntries} empty, {file.Warnings.Count} warnings");
        }
        output.WriteLine($"TOTAL {images} images, {empty} empty, {free} in free space, {unknown} unknown format");
        Assert.True(images > 0);
        Assert.Equal(0, unknown);
    }
}
