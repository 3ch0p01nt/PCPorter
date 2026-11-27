using System.Globalization;
using static PCPorter.TestKit.ChromiumFixture;

namespace PCPorter.TestKit;

// bob's browsers on the fake old drive (tier 3 for the web history report): Chrome Default with live and deleted visits,
// a keyword search, two downloads (one still on disk), bookmarks, a session file and Web Data; a Firefox profile with
// visits, a bookmark, form history and a session file; Internet Explorer's WebCacheV01.dat (clean shutdown). Bait files
// hold the canary: Login Data, Cookies, key4.db, logins.json, Local State's key, and Web Data's card tables and password field.
public sealed partial class OldPcDrive
{
    public static readonly DateTimeOffset HistoryT0 = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
    public const string ChromeUserData = @"C:\Users\bob\AppData\Local\Google\Chrome\User Data";
    public const string ChromeProfile = ChromeUserData + @"\Default";
    public const string FirefoxProfile = @"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x1y2z3.default-release";
    public const string WebCacheFolder = @"C:\Users\bob\AppData\Local\Microsoft\Windows\WebCache";
    public const string KeptDownload = @"C:\Users\bob\Downloads\photos.zip";
    public const string GoneDownload = @"C:\Users\bob\Downloads\gone-setup.exe";

    /// <summary>Filler pages, one typed visit each at <see cref="HistoryT0"/> + 2 h + i minutes; the <see cref="FillerDeleted"/> ones are deleted afterwards.</summary>
    public const int Fillers = 20;
    public static string FillerUrl(int i) => $"https://site{i}.example/page/{i}";
    public static bool FillerDeleted(int i) => i % 5 < 2;                       // 8 of 20, in pairs of neighbouring rows
    public static DateTimeOffset FillerTime(int i) => HistoryT0.AddHours(2).AddMinutes(i);

    /// <summary>Files PCPorter must never open (old-PC paths).</summary>
    public static readonly string[] BaitFiles =
    [
        ChromeProfile + @"\Login Data", ChromeProfile + @"\Cookies", ChromeProfile + @"\Network\Cookies",
        FirefoxProfile + @"\key4.db", FirefoxProfile + @"\logins.json",
    ];

    void PlantBrowsers()
    {
        var t = HistoryT0;
        var chrome = At(ChromeProfile);
        const uint Typed = ChainStart | ChainEnd | 1, Link = ChainStart | ChainEnd | 0;
        using (var f = new ChromiumFixture(chrome))                            // secure_delete OFF: deleted rows stay in free space
        {
            var news = f.Url("https://news.example/", "News front page", t.AddMinutes(40));
            f.Visit(news, t, Typed, durationMicros: 30_000_000);
            f.Visit(news, t.AddMinutes(20), Typed);
            f.Visit(news, t.AddMinutes(40), Link);
            f.Visit(f.Url("https://news.example/story/42", "Big story", t.AddMinutes(41)), t.AddMinutes(41), Link);
            var a = f.Visit(f.Url("http://short.example/abc"), t.AddMinutes(50), ChainStart | 1);            // a typed short link...
            var b = f.Visit(f.Url("https://track.example/r"), t.AddMinutes(50), ServerRedirect | 0, fromVisit: a);   // ...through a tracker
            f.Visit(f.Url("https://landing.example/offer", "Offer", t.AddMinutes(50)), t.AddMinutes(50),
                ServerRedirect | ChainEnd | 0, fromVisit: b);                                                 // ...to the page shown
            var search = f.Url("https://www.google.com/search?q=cheap+flights", "cheap flights - Google Search", t.AddMinutes(60));
            f.Visit(search, t.AddMinutes(60), Typed);
            f.SearchTerm(search, "cheap flights");
            f.Visit(f.Url("https://photos.example/album", "Album", t.AddMinutes(70)), t.AddMinutes(70), Link);
            f.Download(KeptDownload, t.AddMinutes(71), 2048, 2048, 1, "https://photos.example/album", "https://photos.example/album",
                "https://photos.example/download/photos.zip");
            f.Download(GoneDownload, t.AddMinutes(80), 4096, 4096, 1, "https://tools.example/", "https://tools.example/",
                "https://tools.example/gone-setup.exe");

            f.Sql("BEGIN");
            for (int i = 0; i < Fillers; i++)
                f.Visit(f.Url(FillerUrl(i), $"Site {i}", FillerTime(i)), FillerTime(i), Typed, durationMicros: 2_000_000);
            f.Sql("COMMIT");
            var deleted = Enumerable.Range(0, Fillers).Where(FillerDeleted).Select(i => $"'{FillerUrl(i)}'").ToList();
            f.Sql($"DELETE FROM visits WHERE url IN (SELECT id FROM urls WHERE url IN ({string.Join(",", deleted)}))");
            f.Sql($"DELETE FROM urls WHERE url IN ({string.Join(",", deleted)})");
        }
        Text(KeptDownload, "PK");
        File.WriteAllText(Path.Combine(chrome, "Bookmarks"), """
            {"checksum":"x","roots":{
              "bookmark_bar":{"type":"folder","name":"Bookmarks bar","children":[
                {"type":"url","name":"News","url":"https://news.example/","date_added":"ADDED_1"},
                {"type":"folder","name":"Travel","children":[
                  {"type":"url","name":"Flights","url":"https://flights.example/","date_added":"ADDED_2"}]}]},
              "other":{"type":"folder","name":"Other bookmarks","children":[]},
              "synced":{"type":"folder","name":"Mobile bookmarks","children":[]}},"version":1}
            """.Replace("ADDED_1", Invariant(BrowserFixtures.WebKit(t.AddDays(-30)))).Replace("ADDED_2", Invariant(BrowserFixtures.WebKit(t.AddDays(-10)))));
        Directory.CreateDirectory(Path.Combine(chrome, "Sessions"));
        File.WriteAllBytes(Path.Combine(chrome, "Sessions", "Session_13400000000000000"), new SnssBuilder()
            .TabWindow(1, 1).Navigation(1, 0, "https://news.example/story/42", "Big story").Selected(1, 0)
            .TabWindow(1, 2).Navigation(2, 0, "https://mail.example/inbox", "Inbox").Selected(2, 0)
            .Bytes());
        long u = t.ToUnixTimeSeconds();
        WebDataFixture.Create(chrome, Canary,
            ("email", "bob@example.com", 3, u, u + 3600),
            ("password", Canary, 5, u, u + 60));
        // Local State: PCPorter reads only the profile names; the encryption key must stay out of every output.
        File.WriteAllText(At(ChromeUserData + @"\Local State"),
            """{"os_crypt":{"encrypted_key":"KEY"},"profile":{"info_cache":{"Default":{"name":"Bob","avatar_icon":"x"}}}}""".Replace("KEY", Canary));

        using (var f = new FirefoxFixture(At(FirefoxProfile)))
        {
            var fox = t.AddDays(1);
            var wiki = f.Place("https://wiki.example/wiki/Tea", "Tea - Wiki");
            f.Visit(wiki, fox, 2);
            f.Visit(wiki, fox.AddMinutes(5), 1);
            f.Visit(f.Place("https://duckduckgo.com/?q=green+tea", "green tea at DuckDuckGo"), fox.AddMinutes(10), 2);
            f.Visit(f.Place("https://shop.example/teapot", "Teapot"), fox.AddMinutes(15), 1);
            f.Bookmark(3, "https://shop.example/teapot", "Teapot", fox.AddMinutes(16));
            f.Forms(("searchbar-history", "green tea", 2, fox.AddMinutes(9), fox.AddMinutes(10)),
                    ("password", Canary, 1, fox, fox));
            f.Session("sessionstore.jsonlz4",
                """{"version":["sessionrestore",1],"windows":[{"tabs":[{"entries":[{"url":"https://shop.example/teapot","title":"Teapot"}],"index":1,"lastAccessed":LAST}]}]}"""
                    .Replace("LAST", Invariant(fox.AddMinutes(15).ToUnixTimeMilliseconds())));
        }

        var ie = t.AddDays(2);
        WebCacheFixture.Create(At(WebCacheFolder),
            new WebCacheFixture.Container(1, "History",
            [
                new WebCacheFixture.Entry("Visited: bob@https://intranet.example/home", ie, AccessCount: 2),
                new WebCacheFixture.Entry("Visited: bob@https://www.bing.com/search?q=printer+drivers", ie.AddMinutes(3)),
            ]));

        foreach (var bait in BaitFiles) Text(bait, "bait " + Canary);
    }

    static string Invariant(long n) => n.ToString(CultureInfo.InvariantCulture);
}
