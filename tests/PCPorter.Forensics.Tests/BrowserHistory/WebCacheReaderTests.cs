using System.Security.Cryptography;
using Microsoft.Isam.Esent.Interop;
using PCPorter.Collectors.Sources;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;
using static PCPorter.TestKit.WebCacheFixture;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public sealed class WebCacheReaderTests : IDisposable
{
    static readonly DateTimeOffset T0 = new(2025, 6, 1, 8, 0, 0, TimeSpan.Zero);
    readonly string _root = BrowserFixtures.TempDir();
    string Drive => Path.Combine(_root, "drive");
    string Folder => Path.Combine(Drive, @"Users\bob\AppData\Local\Microsoft\Windows\WebCache");
    string Work => Path.Combine(_root, "work");

    public WebCacheReaderTests() => Directory.CreateDirectory(Work);

    public void Dispose() => BrowserFixtures.Delete(_root);

    BrowserProfile Profile => new("bob", BrowserProfileFinder.WebCacheBrowser, BrowserFamily.WebCache, "Default", Folder);

    void BuildTypical() => Create(Folder,
        new Container(1, "History",
        [
            new Entry("Visited: bob@https://news.example/story?id=7", T0, AccessCount: 3),
            new Entry("Visited: bob@https://www.bing.com/search?q=green+tea&form=QBLH", T0.AddMinutes(1)),
            new Entry("Visited: bob@file:///C:/Users/bob/Documents/notes.txt", T0.AddMinutes(2)),
            new Entry("Visited: bob@res://ieframe.dll/navcancl.htm", T0.AddMinutes(3)),
            new Entry("Visited: bob@about:blank", T0.AddMinutes(4)),
            new Entry("Visited: bob@https://login.example/?password=hunter2", T0.AddMinutes(5)),
        ]),
        new Container(5, "MSHist012025060120250602",
        [
            new Entry(":2025060120250602: bob@https://news.example/story?id=7", T0),           // same visit as in History
            new Entry(":2025060120250602: bob@https://older.example/", T0.AddMinutes(-30)),
        ]),
        new Container(7, "Content", [new Entry("https://cdn.example/script.js", T0)]),
        new Container(9, "iedownload",
        [
            new Entry("iedownload:https://dl.example/tool.exe", T0.AddMinutes(10),
                ResponseHeaders: DownloadHeaders("https://dl.example/tool.exe", "https://dl.example/", @"C:\Users\bob\Downloads\tool.exe")),
        ]));

    Dictionary<string, string> Hashes() =>
        Directory.EnumerateFiles(Folder).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));

    [Fact]
    public void Reads_history_containers_downloads_and_searches_and_never_writes_the_originals()
    {
        BuildTypical();
        var before = Hashes();

        var h = WebCacheReader.Read(Profile, Work, path => path.EndsWith("tool.exe") ? true : null);

        Assert.Empty(h.Warnings);
        Assert.Equal(
            ["https://older.example/", "https://news.example/story?id=7", "https://www.bing.com/search?q=green+tea&form=QBLH",
             "file:///C:/Users/bob/Documents/notes.txt", "https://login.example/?password=***"],
            h.Visits.Select(v => v.Url));
        Assert.Equal([T0.AddMinutes(-30), T0, T0.AddMinutes(1), T0.AddMinutes(2), T0.AddMinutes(5)], h.Visits.Select(v => v.When));
        Assert.All(h.Visits, v => Assert.Equal(Origin.Live, v.Origin));
        Assert.Contains("3", h.Visits[1].OriginNote);
        var search = Assert.Single(h.Searches);
        Assert.Equal(("green tea", T0.AddMinutes(1)), (search.Terms, search.When));
        var d = Assert.Single(h.Downloads);
        Assert.Equal(("https://dl.example/tool.exe", @"C:\Users\bob\Downloads\tool.exe", "https://dl.example/", T0.AddMinutes(10), true),
            (d.Url, d.TargetPath, d.Referrer, d.Started, d.StillOnDisk));

        Assert.Equal(before, Hashes());
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    [Fact]
    public void A_dirty_copy_is_repaired_in_the_work_folder_and_the_originals_are_never_written()
    {
        BuildTypical();
        var codes = EseCrash.WhileAttached(Folder, "V01", FileName);
        Assert.Matches(@"^(\d+,){9}\d+", codes);                         // every JET call succeeded (warnings are positive)
        Api.JetGetDatabaseFileInfo(Path.Combine(Folder, FileName), out JET_DBINFOMISC info, JET_DbInfo.Misc);
        Assert.Equal(JET_dbstate.DirtyShutdown, info.dbstate);
        var before = Hashes();

        var h = WebCacheReader.Read(Profile, Work);

        Assert.True(h.Warnings.Count == 0, string.Join(" | ", h.Warnings));
        Assert.Equal(5, h.Visits.Count);
        Assert.Equal(before, Hashes());
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    [Fact]
    public void A_corrupt_file_is_a_warning_not_an_exception()
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllBytes(Path.Combine(Folder, FileName), Enumerable.Range(0, 65536).Select(i => (byte)(i * 13)).ToArray());

        var h = WebCacheReader.Read(Profile, Work);

        Assert.Empty(h.Visits);
        Assert.Contains("could not be read", Assert.Single(h.Warnings));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    [Fact]
    public void An_empty_cache_gives_nothing_and_no_warning()
    {
        Create(Folder);
        var h = WebCacheReader.Read(Profile, Work);
        Assert.Empty(h.Visits);
        Assert.Empty(h.Warnings);
    }

    [Fact]
    public void Offline_drive_files_are_read_through_the_confined_source_only()
    {
        BuildTypical();
        var reads = new List<string>();
        ProfileHistory inside, outside;
        using (SourceFiles.Observe((kind, path) => { if (kind == "read") reads.Add(Path.GetFileName(path)); }))
        {
            using (SourceFiles.Confine(Drive)) inside = WebCacheReader.Read(Profile, Work);
            using (SourceFiles.Confine(Work)) outside = WebCacheReader.Read(Profile, Work);
        }

        Assert.Equal(5, inside.Visits.Count);
        Assert.Contains(FileName, reads);
        Assert.Empty(outside.Visits);
        Assert.Contains("could not be read", Assert.Single(outside.Warnings));
    }

    [Theory]
    [InlineData("Visited: bob@https://a.example/", "https://a.example/")]
    [InlineData(":2025060120250602: bob@http://a.example/x", "http://a.example/x")]
    [InlineData("Visited: bob@https://u@a.example/", "https://u@a.example/")]
    [InlineData("iedownload:https://a.example/f.zip", "https://a.example/f.zip")]
    [InlineData("https://a.example/", "https://a.example/")]
    [InlineData("Visited: bob@file:///C:/x.txt", "file:///C:/x.txt")]
    [InlineData("Visited: bob@res://ieframe.dll/x", null)]
    [InlineData("Visited: bob@about:Tabs", null)]
    [InlineData("Visited: bob@javascript:void(0)", null)]
    [InlineData("Cookie:bob@example.com/", null)]
    public void Addresses_lose_the_cache_prefix_and_other_schemes_are_skipped(string raw, string? expected) =>
        Assert.Equal(expected, WebCacheReader.CleanUrl(raw));
}
