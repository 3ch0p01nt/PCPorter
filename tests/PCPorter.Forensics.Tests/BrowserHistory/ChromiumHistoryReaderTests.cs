using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;
using static PCPorter.TestKit.ChromiumFixture;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class ChromiumHistoryReaderTests
{
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Reads_visits_with_how_they_were_opened_and_masks_secrets()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var profileFolder = Path.Combine(dir, "Default");
            var work = Path.Combine(dir, "work");
            Directory.CreateDirectory(work);
            var profile = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", profileFolder);
            using (var f = new ChromiumFixture(profileFolder))
            {
                var home = f.Url("https://example.com/", "Example");
                f.Visit(home, T0, ChainStart | ChainEnd | 1, durationMicros: 5_500_000);                         // typed
                f.Visit(f.Url("https://news.example.org/a", "News"), T0.AddMinutes(1), ChainStart | ChainEnd | 0);  // link
                f.Visit(f.Url("https://docs.example.net/", "Docs"), T0.AddMinutes(2), ChainStart | ChainEnd | 2);   // bookmark
                var a = f.Visit(f.Url("http://short.example/x"), T0.AddMinutes(3), ChainStart | 1);                // typed, redirected away
                var b = f.Visit(f.Url("https://mid.example/r"), T0.AddMinutes(3), ServerRedirect | 0, fromVisit: a);
                f.Visit(f.Url("https://final.example/page", "Final"), T0.AddMinutes(3), ServerRedirect | ChainEnd | 0, fromVisit: b);
                f.Visit(home, T0.AddMinutes(4), ChainStart | ChainEnd | 8);                                         // reload
                f.Visit(f.Url("https://ads.example/frame"), T0.AddMinutes(5), 3);                                   // auto subframe: hidden
                f.Visit(f.Url("https://ads.example/manual"), T0.AddMinutes(5), 4);                                  // manual subframe: hidden
                f.Visit(f.Url("https://example.com/cb?access_token=abc"), T0.AddMinutes(6), ChainStart | ChainEnd | 0);
                f.Visit(f.Url("https://ftp.example.com/", "files at ftp://user:pw@ftp.example.com"), T0.AddMinutes(7), ChainStart | ChainEnd | 5);
                f.Visit(f.Url("https://form.example/done", "Thanks"), T0.AddMinutes(8), ChainStart | ChainEnd | 7);
                f.Visit(f.Url("https://www.example.com/?q=k"), T0.AddMinutes(9), ChainStart | ChainEnd | 9);     // keyword: typed
            }

            var visits = ChromiumHistoryReader.Read(profile, work).Visits;

            Visit V(string url, string? title, int minute, VisitHow how, long seconds = 0) =>
                new(profile, url, title, T0.AddMinutes(minute), how, seconds);
            Assert.Equal(
            [
                V("https://example.com/", "Example", 0, VisitHow.Typed, 5),
                V("https://news.example.org/a", "News", 1, VisitHow.Link),
                V("https://docs.example.net/", "Docs", 2, VisitHow.Bookmark),
                V("http://short.example/x", null, 3, VisitHow.Typed),
                V("https://mid.example/r", null, 3, VisitHow.Redirect),
                V("https://final.example/page", "Final", 3, VisitHow.Link),
                V("https://example.com/", "Example", 4, VisitHow.Reload),
                V("https://example.com/cb?access_token=***", null, 6, VisitHow.Link),
                V("https://ftp.example.com/", "files at ftp://user:***@ftp.example.com", 7, VisitHow.Generated),
                V("https://form.example/done", "Thanks", 8, VisitHow.FormSubmit),
                V("https://www.example.com/?q=k", null, 9, VisitHow.Typed),
            ], visits);
            Assert.Empty(Directory.GetDirectories(work));       // the copy is removed
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Reads_searches_from_the_terms_table_and_from_addresses_without_duplicates()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            var profile = new BrowserProfile("bob", "Microsoft Edge", BrowserFamily.Chromium, "Default", folder);
            using (var f = new ChromiumFixture(folder))
            {
                var g = f.Url("https://www.google.com/search?q=cheap+flights", "cheap flights - Google", lastVisit: T0.AddMinutes(10));
                f.Visit(g, T0, ChainStart | ChainEnd | 1);
                f.Visit(g, T0.AddMinutes(10), ChainStart | ChainEnd | 1);
                f.SearchTerm(g, "Cheap Flights");
                f.Visit(f.Url("https://www.bing.com/search?q=weather+today"), T0.AddMinutes(20), ChainStart | ChainEnd | 0);
                var odd = f.Url("https://intranet.example/find?x=1", lastVisit: T0.AddMinutes(30));
                f.SearchTerm(odd, "api_key=hunter2");
            }

            var searches = ChromiumHistoryReader.Read(profile, Path.Combine(dir, "work-1")).Searches;

            Assert.Equal(
            [
                new Search(profile, "cheap flights", "Google", T0),
                new Search(profile, "Cheap Flights", "Google", T0.AddMinutes(10)),
                new Search(profile, "weather today", "Bing", T0.AddMinutes(20)),
                new Search(profile, "api_key=***", "intranet.example", T0.AddMinutes(30)),
            ], searches);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Reads_downloads_with_their_first_address_and_whether_the_file_is_still_there()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            var profile = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", folder);
            using (var f = new ChromiumFixture(folder))
            {
                f.Download(@"C:\Users\bob\Downloads\setup.exe", T0, 1000, 1000, 1, "https://vendor.example/download", "https://vendor.example/",
                    "https://vendor.example/get?id=1", "https://cdn.vendor.example/setup.exe");
                f.Download(@"C:\Users\bob\Downloads\big.iso", T0.AddHours(1), 50, 9000, 4, "", "https://isos.example/page",
                    "https://isos.example/big.iso?sig=secret");
                f.Download(@"C:\Users\bob\Downloads\old.zip", T0.AddHours(2), 0, 10, 2, "", "");
            }
            var asked = new List<string>();
            bool? OnDisk(string path) { asked.Add(path); return path.EndsWith("setup.exe") ? true : path.EndsWith("old.zip") ? null : false; }

            var downloads = ChromiumHistoryReader.Read(profile, Path.Combine(dir, "work-2"), OnDisk).Downloads;

            Assert.Equal(
            [
                new Download(profile, "https://vendor.example/get?id=1", "https://vendor.example/download", @"C:\Users\bob\Downloads\setup.exe",
                    T0, 1000, DownloadState.Complete, true),
                new Download(profile, "https://isos.example/big.iso?sig=***", "https://isos.example/page", @"C:\Users\bob\Downloads\big.iso",
                    T0.AddHours(1), 50, DownloadState.Interrupted, false),
                new Download(profile, "", null, @"C:\Users\bob\Downloads\old.zip", T0.AddHours(2), 0, DownloadState.Cancelled, null),
            ], downloads);
            Assert.Equal(3, asked.Count);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Theory]
    [InlineData(0u, VisitHow.Link)]
    [InlineData(1u, VisitHow.Typed)]
    [InlineData(2u, VisitHow.Bookmark)]
    [InlineData(5u, VisitHow.Generated)]
    [InlineData(6u, VisitHow.Other)]
    [InlineData(7u, VisitHow.FormSubmit)]
    [InlineData(8u, VisitHow.Reload)]
    [InlineData(9u, VisitHow.Typed)]
    [InlineData(10u, VisitHow.Typed)]
    [InlineData(ClientRedirect | 0u, VisitHow.Redirect)]
    [InlineData(ClientRedirect | ChainEnd | 1u, VisitHow.Typed)]
    public void Maps_transitions(uint transition, VisitHow expected) =>
        Assert.Equal(expected, ChromiumHistoryReader.MapTransition(transition));

    [Theory]
    [InlineData(3u)]
    [InlineData(4u)]
    [InlineData(ChainStart | ChainEnd | 3u)]
    public void Subframes_are_not_shown(uint transition) => Assert.Null(ChromiumHistoryReader.MapTransition(transition));
}
