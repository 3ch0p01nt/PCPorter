using System.Text;
using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class FirefoxHistoryReaderTests
{
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    const string Canary = "CANARY-ff0c2b";

    static BrowserProfile Profile(string folder) => new("bob", "Firefox", BrowserFamily.Firefox, "default-release", folder);

    [Fact]
    public void Reads_visits_with_visit_types_and_searches_from_addresses()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "abcd.default-release");
            var profile = Profile(folder);
            using (var f = new FirefoxFixture(folder))
            {
                f.Visit(f.Place("https://example.com/", "Example"), T0, 2);                                        // typed
                f.Visit(f.Place("https://news.example.org/", "News"), T0.AddMinutes(1), 1);                         // link
                f.Visit(f.Place("https://docs.example.net/", "Docs"), T0.AddMinutes(2), 3);                         // bookmark
                f.Visit(f.Place("https://ads.example/frame"), T0.AddMinutes(3), 4);                                 // embed: hidden
                var a = f.Visit(f.Place("http://short.example/x"), T0.AddMinutes(4), 2);                            // typed, then redirected
                var b = f.Visit(f.Place("https://mid.example/r"), T0.AddMinutes(4), 5, fromVisit: a);              // permanent redirect target, redirects again
                f.Visit(f.Place("https://final.example/", "Final"), T0.AddMinutes(4), 6, fromVisit: b);            // temporary redirect target
                f.Visit(f.Place("https://files.example/setup.exe"), T0.AddMinutes(5), 7);                          // download
                f.Visit(f.Place("https://frame.example/"), T0.AddMinutes(6), 8);                                    // framed link: hidden
                f.Visit(f.Place("https://example.com/"), T0.AddMinutes(7), 9);                                      // reload (same address, second place row)
                f.Visit(f.Place("https://duckduckgo.com/?q=green+tea&t=h_", "green tea at DuckDuckGo"), T0.AddMinutes(8), 1);
                f.Visit(f.Place("https://login.example/cb?access_token=abc", "user:pw@ login"), T0.AddMinutes(9), 1);
            }

            var h = FirefoxHistoryReader.Read(profile, Path.Combine(dir, "work"));

            Visit V(string url, string? title, int minute, VisitHow how) => new(profile, url, title, T0.AddMinutes(minute), how, 0);
            Assert.Equal(
            [
                V("https://example.com/", "Example", 0, VisitHow.Typed),
                V("https://news.example.org/", "News", 1, VisitHow.Link),
                V("https://docs.example.net/", "Docs", 2, VisitHow.Bookmark),
                V("http://short.example/x", null, 4, VisitHow.Redirect),
                V("https://mid.example/r", null, 4, VisitHow.Redirect),
                V("https://final.example/", "Final", 4, VisitHow.Link),
                V("https://files.example/setup.exe", null, 5, VisitHow.Other),
                V("https://example.com/", null, 7, VisitHow.Reload),
                V("https://duckduckgo.com/?q=green+tea&t=h_", "green tea at DuckDuckGo", 8, VisitHow.Link),
                V("https://login.example/cb?access_token=***", "user:pw@ login", 9, VisitHow.Link),
            ], h.Visits);
            Assert.Equal([new Search(profile, "green tea", "DuckDuckGo", T0.AddMinutes(8))], h.Searches);
            Assert.Empty(h.Warnings);
            Assert.Empty(Directory.GetDirectories(Path.Combine(dir, "work")));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Theory]
    [InlineData(1, false, VisitHow.Link)]
    [InlineData(2, false, VisitHow.Typed)]
    [InlineData(3, false, VisitHow.Bookmark)]
    [InlineData(5, false, VisitHow.Link)]
    [InlineData(6, false, VisitHow.Link)]
    [InlineData(7, false, VisitHow.Other)]
    [InlineData(9, false, VisitHow.Reload)]
    [InlineData(42, false, VisitHow.Other)]
    [InlineData(1, true, VisitHow.Redirect)]
    [InlineData(5, true, VisitHow.Redirect)]
    public void Maps_visit_types(int type, bool redirectedAway, VisitHow expected) =>
        Assert.Equal(expected, FirefoxHistoryReader.MapVisitType(type, redirectedAway));

    [Theory]
    [InlineData(4)]
    [InlineData(8)]
    public void Embedded_and_framed_visits_are_not_shown(int type) => Assert.Null(FirefoxHistoryReader.MapVisitType(type, false));

    [Fact]
    public void Reads_bookmarks_with_folder_paths_but_not_tags_or_queries()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "p.default");
            var profile = Profile(folder);
            using (var f = new FirefoxFixture(folder))
            {
                f.Bookmark(3, "https://toolbar.example/", "On the toolbar", T0);
                var work = f.NewFolder(2, "Work");
                var admin = f.NewFolder(work, "Admin");
                f.Bookmark(admin, "http://admin:hunter2@router.example/", "Router", T0.AddDays(1));
                f.Bookmark(5, "https://other.example/", "Other", T0.AddDays(2));
                f.Bookmark(6, "https://phone.example/", "Phone", T0.AddDays(3));
                var tag = f.NewFolder(4, "cooking");
                f.Bookmark(tag, "https://recipe.example/", "tag entry", T0.AddDays(4));                          // a tag, not a bookmark
                f.Bookmark(3, "place:sort=8&maxResults=10", "Most Visited", T0.AddDays(5));                       // a saved query
            }

            var bookmarks = FirefoxHistoryReader.Read(profile, Path.Combine(dir, "work")).Bookmarks;

            Assert.Equal(
            [
                new Bookmark(profile, "On the toolbar", "https://toolbar.example/", "Bookmarks toolbar", T0),
                new Bookmark(profile, "Router", "http://admin:***@router.example/", "Bookmarks menu/Work/Admin", T0.AddDays(1)),
                new Bookmark(profile, "Other", "https://other.example/", "Other bookmarks", T0.AddDays(2)),
                new Bookmark(profile, "Phone", "https://phone.example/", "Mobile bookmarks", T0.AddDays(3)),
            ], bookmarks);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Reads_downloads_from_annotations()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "p.default");
            var profile = Profile(folder);
            using (var f = new FirefoxFixture(folder))
            {
                f.Download("https://vendor.example/setup.exe?sig=secret", "file:///C:/Users/bob/Downloads/my%20setup.exe", T0,
                    $$"""{"state":1,"endTime":{{T0.AddMinutes(1).ToUnixTimeMilliseconds()}},"fileSize":12345}""");
                f.Download("https://isos.example/big.iso", "file:///C:/Users/bob/Downloads/big.iso", T0.AddHours(1), """{"state":3}""");
                f.Download("https://x.example/odd.bin", "file:///C:/Users/bob/Downloads/odd.bin", T0.AddHours(2), "not json");
                f.Download("https://x.example/nometa.bin", "file:///C:/Users/bob/Downloads/nometa.bin", T0.AddHours(3), null);
            }
            bool? OnDisk(string path) => path.EndsWith("setup.exe") ? true : false;

            var downloads = FirefoxHistoryReader.Read(profile, Path.Combine(dir, "work"), OnDisk).Downloads;

            Assert.Equal(
            [
                new Download(profile, "https://vendor.example/setup.exe?sig=***", null, @"C:\Users\bob\Downloads\my setup.exe", T0, 12345, DownloadState.Complete, true),
                new Download(profile, "https://isos.example/big.iso", null, @"C:\Users\bob\Downloads\big.iso", T0.AddHours(1), 0, DownloadState.Cancelled, false),
                new Download(profile, "https://x.example/odd.bin", null, @"C:\Users\bob\Downloads\odd.bin", T0.AddHours(2), 0, DownloadState.Unknown, false),
                new Download(profile, "https://x.example/nometa.bin", null, @"C:\Users\bob\Downloads\nometa.bin", T0.AddHours(3), 0, DownloadState.Unknown, false),
            ], downloads);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Reads_form_history_with_the_same_field_filter()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "p.default");
            var profile = Profile(folder);
            using (var f = new FirefoxFixture(folder))
                f.Forms(("searchbar-history", "green tea", 3, T0, T0.AddDays(1)),
                        ("email", "bob@example.com", 1, T0, T0),
                        ("password", Canary, 5, T0, T0),
                        ("pin", Canary, 1, T0, T0),
                        ("comment", "4111111111111111", 1, T0, T0));
            var h = FirefoxHistoryReader.Read(profile, Path.Combine(dir, "work"));

            Assert.Equal(
            [
                new FormEntry(profile, "searchbar-history", "green tea", 3, T0, T0.AddDays(1)),
                new FormEntry(profile, "email", "bob@example.com", 1, T0, T0),
            ], h.Forms);
            Assert.Contains(h.Notes, n => n.StartsWith("3 saved form entries", StringComparison.Ordinal));
            Assert.DoesNotContain(Canary, JsonSerializer.Serialize(new { h.Forms, h.Notes }));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    const string SessionJson = """
        {"version":["sessionrestore",1],
         "windows":[
           {"tabs":[
              {"entries":[{"url":"https://example.com/","title":"Example"},{"url":"https://example.com/next","title":"Next"}],"index":1,"lastAccessed":LA1},
              {"entries":[{"url":"https://mail.example.org/?token=abc","title":"Mail"}],"lastAccessed":LA2},
              {"entries":[]}],
            "_closedTabs":[{"state":{"entries":[{"url":"https://closed.example/","title":""}],"index":1},"closedAt":CA1,"title":"x"}]},
           {"tabs":[{"entries":[{"url":"about:newtab"}],"index":7}]}],
         "_closedWindows":[{"tabs":[{"entries":[{"url":"https://w3.example/","title":"W3"}],"index":1}],"closedAt":CA2}]}
        """;

    static string Session() => SessionJson
        .Replace("LA1", T0.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture))
        .Replace("LA2", T0.AddMinutes(1).ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture))
        .Replace("CA1", T0.AddMinutes(2).ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture))
        .Replace("CA2", T0.AddMinutes(3).ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture));

    [Fact]
    public void Session_json_gives_open_and_recently_closed_tabs()
    {
        var profile = Profile(@"C:\nowhere");
        var tabs = FirefoxHistoryReader.ParseSession(profile, Encoding.UTF8.GetBytes(Session()));
        Assert.Equal(
        [
            new OpenTab(profile, "https://example.com/", "Example", 1, TabState.Open, T0),
            new OpenTab(profile, "https://mail.example.org/?token=***", "Mail", 1, TabState.Open, T0.AddMinutes(1)),
            new OpenTab(profile, "https://closed.example/", null, 1, TabState.RecentlyClosed, T0.AddMinutes(2)),
            new OpenTab(profile, "about:newtab", null, 2, TabState.Open, null),
            new OpenTab(profile, "https://w3.example/", "W3", 3, TabState.RecentlyClosed, T0.AddMinutes(3)),
        ], tabs);
    }

    [Fact]
    public void The_newest_session_file_that_unpacks_is_used_and_a_damaged_one_is_a_note()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "p.default");
            var profile = Profile(folder);
            using (var f = new FirefoxFixture(folder))
            {
                var old = f.Session(@"sessionstore-backups\previous.jsonlz4", """{"windows":[{"tabs":[{"entries":[{"url":"https://old.example/"}]}]}]}""");
                var good = f.Session("sessionstore.jsonlz4", Session());
                var broken = Path.Combine(folder, @"sessionstore-backups\recovery.jsonlz4");
                File.WriteAllBytes(broken, [.. "mozLz40\0"u8, 100, 0, 0, 0, 0x10, 0x41, 9, 9]);            // a match pointing before the start
                File.SetLastWriteTimeUtc(old, T0.UtcDateTime);
                File.SetLastWriteTimeUtc(good, T0.AddHours(1).UtcDateTime);
                File.SetLastWriteTimeUtc(broken, T0.AddHours(2).UtcDateTime);
            }

            var h = FirefoxHistoryReader.Read(profile, Path.Combine(dir, "work"));

            Assert.Equal(5, h.Tabs.Count);
            Assert.DoesNotContain(h.Tabs, t => t.Url.Contains("old.example"));
            Assert.Contains(h.Notes, n => n.Contains("recovery.jsonlz4") && n.Contains("could not be unpacked"));
            Assert.Empty(h.Warnings);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Never_opens_password_certificate_or_cookie_files()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "p.default");
            using (var f = new FirefoxFixture(folder))
            {
                f.Visit(f.Place("https://example.com/"), T0, 1);
                f.Forms(("email", "bob@example.com", 1, T0, T0));
                f.Session("sessionstore.jsonlz4", Session());
            }
            foreach (var bait in new[] { "logins.json", "logins-backup.json", "key4.db", "cert9.db", "cookies.sqlite" })
                BrowserFixtures.Touch(folder, bait, Canary);
            var reads = new List<string>();

            ProfileHistory h;
            using (SourceFiles.Observe((kind, path) => { if (kind == "read") reads.Add(Path.GetFileName(path)); }))
                h = FirefoxHistoryReader.Read(Profile(folder), Path.Combine(dir, "work"));

            Assert.Single(h.Visits);
            Assert.Equal(["formhistory.sqlite", "places.sqlite", "sessionstore.jsonlz4"], reads.Distinct().Order(StringComparer.Ordinal));
            Assert.DoesNotContain(Canary, JsonSerializer.Serialize(h));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void The_form_history_query_names_only_its_table()
    {
        var tables = System.Text.RegularExpressions.Regex.Matches(FirefoxHistoryReader.FormSql, @"(?i)\b(?:FROM|JOIN)\s+(\w+)")
            .Select(m => m.Groups[1].Value).ToList();
        Assert.Equal([FirefoxHistoryReader.FormTable], tables);
    }
}
