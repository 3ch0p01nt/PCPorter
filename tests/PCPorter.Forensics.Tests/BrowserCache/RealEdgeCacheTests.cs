using System.Windows.Media.Imaging;
using PCPorter.Forensics.BrowserCache;
using PCPorter.Forensics.Images;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.BrowserCache;

/// <summary>Runs only when this PC has an Edge cache. Reads it read-only; writes nothing.</summary>
public sealed class LocalEdgeCacheFactAttribute : FactAttribute
{
    public static string ProfileFolder => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public LocalEdgeCacheFactAttribute()
    {
        string cache = Path.Combine(ProfileFolder, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache", "Cache_Data", "index");
        if (!File.Exists(cache)) Skip = "No Edge cache on this PC.";
    }
}

public class RealEdgeCacheTests(ITestOutputHelper output)
{
    [LocalEdgeCacheFact, Trait("Category", "Live")]
    public void Images_in_this_pcs_edge_cache_decode()
    {
        var warnings = new List<string>();
        var context = new ImageSourceContext(Environment.UserName, LocalEdgeCacheFactAttribute.ProfileFolder, warnings);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        int scanned = new ChromiumCacheSource().Collect(new ImageSourceContext(Environment.UserName, LocalEdgeCacheFactAttribute.ProfileFolder, [])).Count();
        output.WriteLine($"scan only: {scanned} images in {sw.ElapsedMilliseconds} ms");
        int total = 0, decoded = 0, withTimes = 0, withUrl = 0;
        var byType = new Dictionary<string, int>();
        foreach (var e in new ChromiumCacheSource().Collect(context))
        {
            total++;
            if (e.FirstSeenUtc is not null && e.LastSeenUtc is not null) withTimes++;
            if (e.Url?.StartsWith("http", StringComparison.OrdinalIgnoreCase) == true) withUrl++;
            byType[e.ContentType ?? "?"] = byType.GetValueOrDefault(e.ContentType ?? "?") + 1;
            try
            {
                using var ms = new MemoryStream(e.ImageBytes!);
                var frame = BitmapDecoder.Create(ms, BitmapCreateOptions.None, BitmapCacheOption.OnLoad).Frames[0];
                if (frame.PixelWidth > 0) decoded++;
            }
            catch (Exception ex) when (ex is NotSupportedException or FileFormatException or ArgumentException or InvalidOperationException or IOException)
            {
                // SVG, AVIF, ICO variants etc. are not decodable by WPF; counted only.
            }
        }
        // Counts only: never print URLs or paths.
        output.WriteLine($"{total} images, {decoded} decoded by WPF, {withTimes} with both times, {withUrl} with http URL, {warnings.Count} warnings");
        foreach (var (type, count) in byType.OrderByDescending(kv => kv.Value)) output.WriteLine($"  {type}: {count}");
        Assert.True(decoded > 0);
    }
}
