using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Tests.Images;

public class ScreenshotSourceTests
{
    private static readonly byte[] TinyPng = ImageTestData.Png(8, 6, (x, y) => (x + y) / 14.0);
    private static readonly byte[] TinyJpeg = ImageTestData.Jpeg(8, 6, (x, y) => (x * y) / 35.0);

    [Fact]
    public void Collects_screenshots_and_snips_with_file_times()
    {
        using var profile = new TempProfile();
        var shot = profile.Write(@"Pictures\Screenshots\Screenshot 2026-11-01 101010.png", TinyPng);
        profile.Write(@"OneDrive\Pictures\Screenshots\Screenshot (2).jpg", TinyJpeg);
        profile.Write(@"Pictures\Screenshots\desktop.ini", [1, 2, 3]);
        const string snips = @"AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\TempState";
        profile.Write(snips + @"\Snips\a1b2c3", TinyPng);                // extension-less picture
        profile.Write(snips + @"\settings", "not a picture"u8.ToArray()); // extension-less non-picture
        profile.Write(snips + @"\notes.json", "{}"u8.ToArray());

        var created = new DateTime(2026, 11, 1, 10, 10, 10, DateTimeKind.Utc);
        var modified = new DateTime(2026, 11, 2, 8, 0, 0, DateTimeKind.Utc);
        File.SetCreationTimeUtc(shot, created);
        File.SetLastWriteTimeUtc(shot, modified);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        var items = new ScreenshotSource().Collect(ctx).ToList();

        Assert.Equal(3, items.Count);
        Assert.Empty(ctx.Warnings);
        Assert.All(items, e =>
        {
            Assert.Equal(EvidenceLevel.OnScreen, e.Evidence);
            Assert.Equal("bob", e.User);
            Assert.Equal("screenshot file created / last changed", e.TimeMeaning);
            Assert.NotNull(e.ImageBytes);
        });

        var local = Assert.Single(items, e => e.Source == "Screenshots folder");
        Assert.Equal(shot, local.OriginalPath);
        Assert.Equal(TinyPng, local.ImageBytes);
        Assert.Equal("image/png", local.ContentType);
        Assert.Equal(created, local.FirstSeenUtc!.Value.UtcDateTime);
        Assert.Equal(modified, local.LastSeenUtc!.Value.UtcDateTime);

        Assert.Equal("image/jpeg", Assert.Single(items, e => e.Source == "OneDrive Screenshots folder").ContentType);
        var snip = Assert.Single(items, e => e.Source == "Snipping Tool");
        Assert.Equal("image/png", snip.ContentType);
        Assert.Equal(TinyPng, snip.ImageBytes);
    }

    [Fact]
    public void Skips_files_over_30_mb_with_a_warning()
    {
        using var profile = new TempProfile();
        var big = profile.Write(@"Pictures\Screenshots\huge.png", TinyPng);
        using (var fs = new FileStream(big, FileMode.Open, FileAccess.Write)) fs.SetLength(31L * 1024 * 1024);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        Assert.Empty(new ScreenshotSource().Collect(ctx));
        Assert.Contains(ctx.Warnings, w => w.Contains("30 MB"));
    }

    [Fact]
    public void Reads_a_file_another_program_has_open_for_writing()
    {
        using var profile = new TempProfile();
        var path = profile.Write(@"Pictures\Screenshots\open.png", TinyPng);
        using var holder = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        Assert.Single(new ScreenshotSource().Collect(ctx));
    }

    [Fact]
    public void Missing_profile_yields_nothing_and_does_not_throw()
    {
        var ctx = new ImageSourceContext("bob", Path.Combine(Path.GetTempPath(), "no-such-" + Guid.NewGuid().ToString("N")), new List<string>());
        Assert.Empty(new ScreenshotSource().Collect(ctx));
        Assert.Empty(ctx.Warnings);
    }
}
