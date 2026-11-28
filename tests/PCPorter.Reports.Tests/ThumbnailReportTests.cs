using System.Text.Json;
using System.Text.RegularExpressions;
using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Forensics.Thumbcache;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class GalleryReportTests
{
    static readonly ReportMeta Meta = new("BOB-LAPTOP", new DateTimeOffset(2026, 11, 26, 12, 0, 0, TimeSpan.Zero), "0.1.0", ["bob"], false);

    static GalleryScanResult Result(string? path, string? url = null)
    {
        var img = new GalleryImage("256", 256, 192, "00000000000000aa.jpg", ImageFormat.Jpeg, false);
        return new([new GalleryItem("t-bob-aa", "thumbnail", "File Explorer thumbnails", EvidenceLevel.Displayed, "bob", "00000000000000aa",
                path, url, OriginalStatus.Deleted, false, img, [img],
                new DateWindow(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1), "Low", ["cache file created"]), null)],
            [new CacheFileSummary("bob", "thumbcache_256.db", 0x20, 1, 0, 0)], [], ["a note"]);
    }

    static JsonDocument EmbeddedData(string html)
    {
        var m = Regex.Match(html, "<script type=\"application/json\" id=\"data\">(.*?)</script>", RegexOptions.Singleline);
        Assert.True(m.Success, "data block missing");
        return JsonDocument.Parse(m.Groups[1].Value);
    }

    [Fact]
    public void Embeds_compact_items_with_string_enums()
    {
        using var doc = EmbeddedData(GalleryReport.Render(Result(@"C:\Pics\cat.jpg"), Meta));
        var item = doc.RootElement.GetProperty("items")[0];
        Assert.Equal(@"C:\Pics\cat.jpg", item.GetProperty("originalPath").GetString());
        Assert.Equal("Deleted", item.GetProperty("status").GetString());
        Assert.Equal("Displayed", item.GetProperty("evidence").GetString());
        Assert.Equal("00000000000000aa.jpg", item.GetProperty("images")[0].GetProperty("f").GetString());
        Assert.False(item.TryGetProperty("url", out _));                 // nulls omitted
        Assert.Equal("a note", doc.RootElement.GetProperty("notes")[0].GetString());
        Assert.Equal("BOB-LAPTOP", doc.RootElement.GetProperty("meta").GetProperty("computer").GetString());
    }

    [Fact]
    public void Hostile_paths_and_urls_cannot_break_out_of_the_script_block()
    {
        var html = GalleryReport.Render(Result(@"C:\x\</script><script>alert(1)</script>.jpg", "https://e.com/<script>alert(2)</script>"), Meta);
        Assert.DoesNotContain("<script>alert(", html);
        using var doc = EmbeddedData(html);
        Assert.Contains("alert(1)", doc.RootElement.GetProperty("items")[0].GetProperty("originalPath").GetString());
    }

    [Fact]
    public void Report_loads_nothing_from_the_network_and_has_a_strict_policy()
    {
        var html = GalleryReport.Render(Result(null), Meta);
        Assert.DoesNotMatch(@"(src|href)\s*=\s*[""']https?:", html);
        Assert.Contains("default-src 'none'", html);
        Assert.Contains("base-uri 'none'", html);
        Assert.DoesNotContain("__PCPORTER_DATA__", html);
    }

    [Fact]
    public void Every_original_status_has_a_label_help_text_and_filter()
    {
        var html = GalleryReport.Render(Result(null), Meta);
        foreach (var s in Enum.GetNames<OriginalStatus>())
        {
            Assert.Matches($@"statusText = \{{[^}}]*\b{s}: """, html);
            Assert.Matches($@"statusHelp = \{{[^}}]*\b{s}: """, html);
            Assert.Contains($"<option value=\"{s}\">", html);
            Assert.Contains($".s-{s} {{", html);
        }
    }

    [Fact]
    public void WriteFile_refuses_to_overwrite()
    {
        var dir = Directory.CreateTempSubdirectory("pcporter-report").FullName;
        try
        {
            var path = GalleryReport.WriteFile(Result(null), Meta, dir);
            Assert.True(new FileInfo(path).Length > 1000);
            Assert.Throws<IOException>(() => GalleryReport.WriteFile(Result(null), Meta, dir));
        }
        finally { Directory.Delete(dir, true); }
    }
}
