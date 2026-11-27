using PCPorter.Forensics.BrowserCache;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Tests.BrowserCache;

public class FirefoxCacheSourceTests
{
    private static readonly DateTimeOffset Fetched = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Modified = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);

    private static (string Profile, string Entries) FirefoxProfile()
    {
        string profile = Fixture.TempDir();
        string entries = Path.Combine(profile, "AppData", "Local", "Mozilla", "Firefox", "Profiles", "ab12cd34.default-release", "cache2", "entries");
        Directory.CreateDirectory(entries);
        return (profile, entries);
    }

    private static (List<ImageEvidence> Items, List<string> Warnings) Run(string profile)
    {
        var warnings = new List<string>();
        var items = new FirefoxCacheSource().Collect(new ImageSourceContext("bob", profile, warnings)).ToList();
        return (items, warnings);
    }

    private static string Head(string type, string? encoding = null) =>
        $"HTTP/1.1 200 OK\r\nContent-Type: {type}\r\n" + (encoding is null ? "" : $"Content-Encoding: {encoding}\r\n") +
        "Date: Tue, 24 Nov 2026 12:00:00 GMT\r\n";

    [Fact]
    public void Image_entry_is_found_with_url_and_times()
    {
        var (profile, entries) = FirefoxProfile();
        var png = Fixture.Png(400);
        FirefoxEntryBuilder.Write(Path.Combine(entries, "0A1B2C3D4E5F60718293A4B5C6D7E8F901234567"),
            "O^partitionKey=%28https%2Csite.test%29,a,:https://img.site.test/p.png", png, Head("image/png"), 3, Fetched, Modified);

        var (items, warnings) = Run(profile);

        var e = Assert.Single(items);
        Assert.Empty(warnings);
        Assert.Equal("https://img.site.test/p.png", e.Url);
        Assert.Equal("Firefox cache (ab12cd34.default-release)", e.Source);
        Assert.Equal(EvidenceLevel.LoadedByWebPage, e.Evidence);
        Assert.Equal(Fetched, e.LastSeenUtc);
        Assert.Equal(Modified, e.FirstSeenUtc); // earlier than the fixture file's creation time
        Assert.Equal("first and last loaded from Firefox cache", e.TimeMeaning);
        Assert.Equal("image/png", e.ContentType);
        Assert.Equal(png, e.ImageBytes);
        Assert.Contains("fetched 3 times", e.Note);
    }

    [Fact]
    public void Non_images_are_skipped_and_gzip_is_decoded()
    {
        var (profile, entries) = FirefoxProfile();
        var jpeg = Fixture.Jpeg(2000);
        FirefoxEntryBuilder.Write(Path.Combine(entries, "A1"), "a,:https://site.test/index.html", Fixture.Html(), Head("text/html"), 1, Fetched, Modified);
        FirefoxEntryBuilder.Write(Path.Combine(entries, "A2"), "a,:https://site.test/g.jpg", Fixture.Gzip(jpeg), Head("image/jpeg", "gzip"), 1, Fetched, Modified);
        FirefoxEntryBuilder.Write(Path.Combine(entries, "A3"), ":https://site.test/blob", Fixture.Png(), Head("application/octet-stream"), 1, Fetched, Modified);

        var (items, warnings) = Run(profile);

        Assert.Empty(warnings);
        Assert.Equal(2, items.Count);
        Assert.Equal(jpeg, items.Single(i => i.Url == "https://site.test/g.jpg").ImageBytes);
        Assert.Equal("image/png", items.Single(i => i.Url == "https://site.test/blob").ContentType);
    }

    [Fact]
    public void Body_spanning_several_chunks_is_read()
    {
        var (profile, entries) = FirefoxProfile();
        var big = Fixture.Jpeg(600_000); // three 256 KB chunks -> three chunk hashes
        FirefoxEntryBuilder.Write(Path.Combine(entries, "B1"), "a,:https://site.test/big.jpg", big, Head("image/jpeg"), 2, Fetched, Modified);

        var (items, _) = Run(profile);

        Assert.Equal(big, Assert.Single(items).ImageBytes);
    }

    [Fact]
    public void Corrupt_and_truncated_files_give_warnings_not_exceptions()
    {
        var (profile, entries) = FirefoxProfile();
        FirefoxEntryBuilder.Write(Path.Combine(entries, "OK"), "a,:https://site.test/ok.png", Fixture.Png(), Head("image/png"), 1, Fetched, Modified);
        File.WriteAllBytes(Path.Combine(entries, "BAD1"), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        File.WriteAllBytes(Path.Combine(entries, "BAD2"), [1, 2, 3]);
        var good = File.ReadAllBytes(Path.Combine(entries, "OK"));
        File.WriteAllBytes(Path.Combine(entries, "BAD3"), good[..(good.Length - 30)]); // metadata cut off
        File.WriteAllBytes(Path.Combine(entries, "EMPTY"), []);

        var (items, warnings) = Run(profile);

        Assert.Equal("https://site.test/ok.png", Assert.Single(items).Url);
        Assert.Contains(warnings, w => w.Contains("3 cache files could not be read", StringComparison.Ordinal));
    }

    [Fact]
    public void Random_garbage_never_throws()
    {
        var (profile, entries) = FirefoxProfile();
        var rng = new Random(42);
        for (int i = 0; i < 200; i++)
        {
            FirefoxEntryBuilder.Write(Path.Combine(entries, $"F{i}"), $"a,:https://site.test/{i}.png", Fixture.Png(100 + i), Head("image/png"), 1, Fetched, Modified);
            var bytes = File.ReadAllBytes(Path.Combine(entries, $"F{i}"));
            for (int k = 0; k < 6; k++) bytes[rng.Next(bytes.Length)] = (byte)rng.Next(256);
            if (i % 3 == 0) bytes = bytes[..rng.Next(bytes.Length)];
            File.WriteAllBytes(Path.Combine(entries, $"F{i}"), bytes);
        }

        var (items, _) = Run(profile); // must not throw
        Assert.True(items.Count <= 200);
    }
}
