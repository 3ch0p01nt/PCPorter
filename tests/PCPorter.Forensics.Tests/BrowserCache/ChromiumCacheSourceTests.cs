using PCPorter.Forensics.BrowserCache;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Tests.BrowserCache;

public class ChromiumCacheSourceTests
{
    private static readonly DateTimeOffset Created = new(2026, 11, 20, 8, 30, 15, TimeSpan.Zero);
    private static readonly DateTimeOffset Used = new(2026, 11, 24, 17, 5, 0, TimeSpan.Zero);

    private static (string Profile, string Cache) EdgeProfile(string profileName = "Default")
    {
        string profile = Fixture.TempDir();
        string cache = Path.Combine(profile, "AppData", "Local", "Microsoft", "Edge", "User Data", profileName, "Cache", "Cache_Data");
        return (profile, cache);
    }

    private static (List<ImageEvidence> Items, List<string> Warnings) Run(string profile)
    {
        var warnings = new List<string>();
        var items = new ChromiumCacheSource().Collect(new ImageSourceContext("bob", profile, warnings)).ToList();
        return (items, warnings);
    }

    [Fact]
    public void Image_entry_is_found_with_url_and_times()
    {
        var (profile, cache) = EdgeProfile();
        var png = Fixture.Png();
        new BlockfileBuilder()
            .Add("1/0/_dk_https://site.test https://site.test https://img.site.test/pic.png", png, "image/png", Created, Used)
            .Write(cache);

        var (items, warnings) = Run(profile);

        var e = Assert.Single(items);
        Assert.Empty(warnings);
        Assert.Equal("https://img.site.test/pic.png", e.Url);
        Assert.Equal("Edge cache (Default)", e.Source);
        Assert.Equal(EvidenceLevel.LoadedByWebPage, e.Evidence);
        Assert.Equal("bob", e.User);
        Assert.Equal(Created, e.FirstSeenUtc);
        Assert.Equal(Used, e.LastSeenUtc);
        Assert.Equal("first and last loaded from Edge cache", e.TimeMeaning);
        Assert.Equal("image/png", e.ContentType);
        Assert.Equal(png, e.ImageBytes);
        Assert.Contains("HTTP 200", e.Note);
    }

    [Fact]
    public void Non_images_and_tiny_bodies_are_skipped_but_sniffed_images_kept()
    {
        var (profile, cache) = EdgeProfile("Profile 2");
        var jpeg = Fixture.Jpeg();
        new BlockfileBuilder()
            .Add("https://site.test/page.html", Fixture.Html(), "text/html", Created, Used)
            .Add("https://site.test/tiny.png", Fixture.Png(40), "image/png", Created, Used)
            .Add("https://site.test/blob", jpeg, "application/octet-stream", Created, Used)
            .Add("https://site.test/script.js", Fixture.Gzip(Fixture.Html()), "application/javascript", Created, Used, "gzip")
            .Write(cache);

        var (items, warnings) = Run(profile);

        var e = Assert.Single(items);
        Assert.Empty(warnings);
        Assert.Equal("https://site.test/blob", e.Url);
        Assert.Equal("image/jpeg", e.ContentType);
        Assert.Equal("Edge cache (Profile 2)", e.Source);
    }

    [Fact]
    public void Gzip_and_brotli_bodies_are_decoded()
    {
        var (profile, cache) = EdgeProfile();
        var png = Fixture.Png(3000);
        var jpeg = Fixture.Jpeg(5000);
        new BlockfileBuilder()
            .Add("https://site.test/a.png", Fixture.Gzip(png), "image/png", Created, Used, "gzip")
            .Add("https://site.test/b.jpg", Fixture.Brotli(jpeg), "image/jpeg; charset=binary", Created, Used, "br")
            .Write(cache);

        var (items, _) = Run(profile);

        Assert.Equal(2, items.Count);
        Assert.Equal(png, items.Single(i => i.Url!.EndsWith("a.png", StringComparison.Ordinal)).ImageBytes);
        var b = items.Single(i => i.Url!.EndsWith("b.jpg", StringComparison.Ordinal));
        Assert.Equal(jpeg, b.ImageBytes);
        Assert.Equal("image/jpeg", b.ContentType);
    }

    [Fact]
    public void External_f_file_body_and_chained_entries_are_read()
    {
        var (profile, cache) = EdgeProfile();
        var big = Fixture.Jpeg(40_000); // > 16 KB goes to an f_ file
        var builder = new BlockfileBuilder().Add("https://site.test/big.jpg", big, "image/jpeg", Created, Used);
        for (int i = 0; i < 5; i++) builder.Add($"https://site.test/{i}.png", Fixture.Png(100 + i), "image/png", Created, Used, forceExternal: i == 3);
        builder.Write(cache);
        Assert.True(File.Exists(Path.Combine(cache, "f_000001")));

        var (items, warnings) = Run(profile);

        Assert.Empty(warnings);
        Assert.Equal(6, items.Count);
        Assert.Equal(big, items.Single(i => i.Url == "https://site.test/big.jpg").ImageBytes);
        Assert.Equal(Fixture.Png(103), items.Single(i => i.Url == "https://site.test/3.png").ImageBytes);
    }

    [Fact]
    public void Long_key_stored_outside_the_entry_is_read()
    {
        var (profile, cache) = EdgeProfile();
        string url = "https://site.test/" + new string('k', 1500) + ".png";
        new BlockfileBuilder().Add(url, Fixture.Png(), "image/png", Created, Used).Write(cache);

        var (items, _) = Run(profile);

        Assert.Equal(url, Assert.Single(items).Url);
    }

    [Fact]
    public void Missing_external_file_gives_warning_not_exception()
    {
        var (profile, cache) = EdgeProfile();
        new BlockfileBuilder()
            .Add("https://site.test/ok.png", Fixture.Png(), "image/png", Created, Used)
            .Add("https://site.test/gone.jpg", Fixture.Jpeg(40_000), "image/jpeg", Created, Used)
            .Write(cache);
        File.Delete(Path.Combine(cache, "f_000001"));

        var (items, warnings) = Run(profile);

        Assert.Equal("https://site.test/ok.png", Assert.Single(items).Url);
        Assert.Contains(warnings, w => w.Contains("missing", StringComparison.Ordinal));
    }

    [Fact]
    public void Truncated_data_file_gives_warning_not_exception()
    {
        var (profile, cache) = EdgeProfile();
        new BlockfileBuilder()
            .Add("https://site.test/a.png", Fixture.Png(), "image/png", Created, Used)
            .Add("https://site.test/b.png", Fixture.Png(), "image/png", Created, Used)
            .Write(cache);
        string data1 = Path.Combine(cache, "data_1");
        File.WriteAllBytes(data1, File.ReadAllBytes(data1)[..(8192 + 300)]); // second entry cut off

        var (items, warnings) = Run(profile);

        Assert.True(items.Count <= 1);
        Assert.Contains(warnings, w => w.Contains("could not be read", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(400)]
    public void Garbage_index_gives_warning_not_exception(int size)
    {
        var (profile, cache) = EdgeProfile();
        new BlockfileBuilder().Add("https://site.test/a.png", Fixture.Png(), "image/png", Created, Used).Write(cache);
        var junk = new byte[size];
        new Random(size).NextBytes(junk);
        File.WriteAllBytes(Path.Combine(cache, "index"), junk);

        var (items, warnings) = Run(profile);

        Assert.Empty(items);
        Assert.NotEmpty(warnings);
    }

    [Fact]
    public void Random_garbage_in_every_file_never_throws()
    {
        for (int seed = 0; seed < 30; seed++)
        {
            var (profile, cache) = EdgeProfile();
            new BlockfileBuilder()
                .Add("https://site.test/a.png", Fixture.Png(), "image/png", Created, Used)
                .Add("https://site.test/b.jpg", Fixture.Jpeg(40_000), "image/jpeg", Created, Used)
                .Add("https://site.test/c.png", Fixture.Gzip(Fixture.Png(900)), "image/png", Created, Used, "gzip")
                .Write(cache);
            var rng = new Random(seed);
            foreach (var file in Directory.GetFiles(cache))
            {
                var bytes = File.ReadAllBytes(file);
                for (int i = 0; i < 40 && bytes.Length > 0; i++) bytes[rng.Next(bytes.Length)] = (byte)rng.Next(256);
                File.WriteAllBytes(file, bytes);
            }
            var (items, _) = Run(profile); // must not throw
            Assert.True(items.Count <= 3);
        }
    }

    [Fact]
    public void Simple_cache_files_are_read()
    {
        var (profile, cache) = EdgeProfile();
        Directory.CreateDirectory(cache);
        var png = Fixture.Png(500);
        SimpleCacheBuilder.Write(Path.Combine(cache, "0123456789abcdef_0"), "1/0/https://img.site.test/s.png", png,
            ["HTTP/1.1 200 OK", "Content-Type: image/png"]);
        SimpleCacheBuilder.Write(Path.Combine(cache, "fedcba9876543210_0"), "https://site.test/x.html", Fixture.Html(),
            ["HTTP/1.1 200 OK", "Content-Type: text/html"]);
        File.WriteAllBytes(Path.Combine(cache, "1111111111111111_0"), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76]);

        var (items, warnings) = Run(profile);

        var e = Assert.Single(items);
        Assert.Equal("https://img.site.test/s.png", e.Url);
        Assert.Equal(png, e.ImageBytes);
        Assert.NotNull(e.FirstSeenUtc);
        Assert.Contains(warnings, w => w.Contains("1 cache files could not be read", StringComparison.Ordinal));
    }

    [Fact]
    public void Teams_and_chrome_folders_are_found()
    {
        string profile = Fixture.TempDir();
        string local = Path.Combine(profile, "AppData", "Local");
        new BlockfileBuilder().Add("https://t.test/a.png", Fixture.Png(), "image/png", Created, Used)
            .Write(Path.Combine(local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams", "EBWebView", "WV2Profile_tfw", "Cache", "Cache_Data"));
        new BlockfileBuilder().Add("https://c.test/a.png", Fixture.Png(), "image/png", Created, Used)
            .Write(Path.Combine(local, "Google", "Chrome", "User Data", "Profile 1", "Cache", "Cache_Data"));
        new BlockfileBuilder().Add("https://x.test/a.png", Fixture.Png(), "image/png", Created, Used)
            .Write(Path.Combine(local, "Google", "Chrome", "User Data", "System Profile", "Cache", "Cache_Data"));

        var (items, _) = Run(profile);

        Assert.Equal(["Chrome cache (Profile 1)", "Teams cache"], items.Select(i => i.Source).Order());
        Assert.Equal("first and last loaded from Teams cache", items.Single(i => i.Source == "Teams cache").TimeMeaning);
    }

    [Fact]
    public void Missing_profile_yields_nothing()
    {
        var (items, warnings) = Run(Path.Combine(Path.GetTempPath(), "pcporter-no-such-profile-" + Guid.NewGuid().ToString("N")));
        Assert.Empty(items);
        Assert.Empty(warnings);
    }
}
