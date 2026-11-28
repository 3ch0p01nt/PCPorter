using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.Reports;
using PCPorter.TestKit;

namespace PCPorter.Reports.Tests;

public sealed class HistoryJobTests : IDisposable
{
    readonly string _drive = Directory.CreateTempSubdirectory("pcporter-histdrive").FullName;
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-histjob").FullName;
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Now = new(2026, 11, 27, 9, 0, 0, TimeSpan.Zero);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var d in new[] { _drive, _out })
            try { Directory.Delete(d, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    static long WebKit(DateTimeOffset t) => t.UtcDateTime.ToFileTimeUtc() / 10;

    /// <summary>A Chromium History database with the tables and columns the reader uses.</summary>
    static void ChromeHistory(string profileFolder, Action<SqliteConnection> fill)
    {
        Directory.CreateDirectory(profileFolder);
        using var c = new SqliteConnection($"Data Source={Path.Combine(profileFolder, "History")};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,term LONGVARCHAR NOT NULL,normalized_term LONGVARCHAR NOT NULL);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,referrer VARCHAR NOT NULL,tab_url VARCHAR NOT NULL);
            CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));
            """;
        cmd.ExecuteNonQuery();
        fill(c);
    }

    static void Sql(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    /// <summary>A minimal SNSS session file: one tab navigation (command 6, a Pickle with tab id, index, url, title).</summary>
    static byte[] SessionFile(string url)
    {
        var u = System.Text.Encoding.UTF8.GetBytes(url);
        var body = new List<byte>();
        body.AddRange(BitConverter.GetBytes(1)); body.AddRange(BitConverter.GetBytes(0));
        body.AddRange(BitConverter.GetBytes(u.Length)); body.AddRange(u);
        while (body.Count % 4 != 0) body.Add(0);
        body.AddRange(BitConverter.GetBytes(0));                                  // empty title
        byte[] pickle = [.. BitConverter.GetBytes(body.Count), .. body];
        return [.. "SNSS"u8, 1, 0, 0, 0, .. BitConverter.GetBytes((ushort)(pickle.Length + 1)), 6, .. pickle];
    }

    /// <summary>Web Data with one ordinary autofill entry, one password field and a payment card table.</summary>
    static void WebData(string profileFolder)
    {
        using var c = new SqliteConnection($"Data Source={Path.Combine(profileFolder, "Web Data")};Pooling=False");
        c.Open();
        Sql(c, "CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value))");
        Sql(c, "CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, card_number_encrypted BLOB)");
        Sql(c, $"INSERT INTO autofill VALUES ('email', 'bob@example.com', 'bob@example.com', {T0.ToUnixTimeSeconds()}, {T0.ToUnixTimeSeconds()}, 3)");
        Sql(c, $"INSERT INTO autofill VALUES ('password', '{Canary}', '', 0, 0, 1)");
        Sql(c, $"INSERT INTO credit_cards VALUES ('g', '{Canary}', CAST('{Canary}' AS BLOB))");
    }

    const string Canary = "CANARY-5d1e77";

    /// <summary>A Firefox profile: places.sqlite with two visits (one a search) and a bookmark; logins.json bait.</summary>
    static void FirefoxPlaces(string profileFolder)
    {
        Directory.CreateDirectory(profileFolder);
        using (var c = new SqliteConnection($"Data Source={Path.Combine(profileFolder, "places.sqlite")};Pooling=False"))
        {
            c.Open();
            Sql(c, "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT)");
            Sql(c, "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER)");
            Sql(c, "CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT)");
            Sql(c, "CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL)");
            Sql(c, "CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0)");
            long pr = T0.ToUnixTimeMilliseconds() * 1000;
            Sql(c, "INSERT INTO moz_places (id, url, title) VALUES (1, 'https://firefox.example/', 'Fox'), (2, 'https://www.bing.com/search?q=green+tea', 'green tea - Bing')");
            Sql(c, $"INSERT INTO moz_historyvisits (place_id, visit_date, visit_type) VALUES (1, {pr + 180_000_000}, 2), (2, {pr + 240_000_000}, 1)");
            Sql(c, "INSERT INTO moz_bookmarks (id, type, parent, title, guid) VALUES (1, 2, 0, '', 'root________'), (2, 2, 1, 'toolbar', 'toolbar_____')");
            Sql(c, $"INSERT INTO moz_bookmarks (id, type, fk, parent, title, dateAdded, guid) VALUES (3, 1, 1, 2, 'Fox', {pr}, 'b')");
        }
        File.WriteAllText(Path.Combine(profileFolder, "logins.json"), Canary);
    }

    FakeSystemSource Source()
    {
        var bob = Path.Combine(_drive, "Users", "bob");
        ChromeHistory(Path.Combine(bob, @"AppData\Local\Google\Chrome\User Data\Default"), c =>
        {
            Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES (1, 'https://example.com/', 'Example', {WebKit(T0)})");
            Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES (2, 'https://www.google.com/search?q=tea', 'tea - Google', {WebKit(T0.AddMinutes(1))})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (1, {WebKit(T0)}, {0x30000001})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (2, {WebKit(T0.AddMinutes(1))}, {0x30000001})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (1, {WebKit(T0.AddMinutes(2))}, {0x30000000})");
            Sql(c, "INSERT INTO keyword_search_terms VALUES (2, 2, 'tea', 'tea')");
            Sql(c, $"INSERT INTO downloads VALUES (1, 'g', 'C:\\Users\\bob\\Downloads\\tool.exe', 'C:\\Users\\bob\\Downloads\\tool.exe', {WebKit(T0)}, 10, 10, 1, '', 'https://example.com/')");
            Sql(c, "INSERT INTO downloads_url_chains VALUES (1, 0, 'https://example.com/tool.exe')");
        });
        var chrome = Path.Combine(bob, @"AppData\Local\Google\Chrome\User Data\Default");
        File.WriteAllText(Path.Combine(chrome, "Bookmarks"),
            """{"roots":{"bookmark_bar":{"children":[{"type":"url","name":"Tea","url":"https://tea.example/","date_added":"13400000000000000"}]}}}""");
        Directory.CreateDirectory(Path.Combine(chrome, "Sessions"));
        File.WriteAllBytes(Path.Combine(chrome, "Sessions", "Session_1"), SessionFile("https://open.example/"));
        WebData(chrome);
        Directory.CreateDirectory(Path.Combine(bob, "Downloads"));
        File.WriteAllText(Path.Combine(bob, "Downloads", "tool.exe"), "MZ");
        // A second profile whose History is damaged: it must not stop the run.
        var edge = Path.Combine(bob, @"AppData\Local\Microsoft\Edge\User Data\Default");
        Directory.CreateDirectory(edge);
        File.WriteAllBytes(Path.Combine(edge, "History"), Enumerable.Range(0, 8192).Select(i => (byte)(i * 7)).ToArray());

        FirefoxPlaces(Path.Combine(bob, @"AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release"));
        return new FakeSystemSource(_drive, users:
        [
            new UserProfile("S-1-5-21-1-2-3-1001", "bob", bob, null, @"C:\Users\bob"),
            new UserProfile("S-1-5-21-1-2-3-1002", "carol", null, "This profile is on another drive.", @"E:\Users\carol"),
        ]);
    }

    [Fact]
    public void Writes_the_report_and_case_rows_and_survives_a_damaged_profile()
    {
        using var source = Source();
        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);

        Assert.True(File.Exists(r.ReportPath));
        Assert.Equal("History.html", Path.GetFileName(r.ReportPath));
        Assert.False(Directory.Exists(Path.Combine(r.CaseFolder, "work")));

        Assert.Equal(5, r.Scan.Visits.Count);
        Assert.Equal(["tea", "green tea"], r.Scan.Searches.Select(s => s.Terms));
        var download = Assert.Single(r.Scan.Downloads);
        Assert.True(download.StillOnDisk);
        Assert.Equal(["Firefox", "Google Chrome", "Microsoft Edge"], r.Scan.Coverage.Select(c => c.Profile.Browser));
        Assert.Equal((2, T0.AddMinutes(3)), (r.Scan.Coverage[0].Visits, r.Scan.Coverage[0].Earliest));
        Assert.Contains("Firefox keeps", r.Scan.Coverage[0].Note);
        Assert.Equal(3, r.Scan.Coverage[1].Visits);
        Assert.Equal(T0, r.Scan.Coverage[1].Earliest);
        Assert.Contains(r.Scan.Warnings, w => w.Contains("Microsoft Edge") && w.Contains("bob"));
        Assert.Contains(r.Scan.Notes, n => n.Contains("carol"));
        Assert.DoesNotContain(r.Scan.Notes, n => n.Contains("not read by this version"));
        Assert.DoesNotContain(r.Scan.Notes, n => n.StartsWith("Firefox history was found", StringComparison.Ordinal));

        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var counts = db.CountByCategory();
        Assert.Equal(5, counts["WebHistory.Visit"]);
        Assert.Equal(2, counts["WebHistory.Search"]);
        Assert.Equal(1, counts["WebHistory.Download"]);
        Assert.Equal(2, counts["WebHistory.Bookmark"]);
        Assert.Equal(1, counts["WebHistory.Tab"]);
        Assert.Equal(1, counts["WebHistory.Form"]);
        var visit = db.Search("example.com").First(a => a.Category == "WebHistory.Visit");
        Assert.Equal("Google Chrome/Default", visit.Source);
        Assert.Equal("bob", visit.User);
        var fox = db.Search("firefox.example").First(a => a.Category == "WebHistory.Visit");
        Assert.Equal("Firefox/default-release", fox.Source);
    }

    /// <summary>Calls back on the reporting thread (Progress&lt;T&gt; would post to the thread pool).</summary>
    sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }

    [Fact]
    public void A_work_folder_that_cannot_be_deleted_is_a_warning_naming_it()
    {
        using var source = Source();
        FileStream? held = null;
        var progress = new SyncProgress(_ =>
        {
            if (held is not null) return;
            var work = Directory.GetDirectories(_out, "work", SearchOption.AllDirectories).Single();
            held = new FileStream(Path.Combine(work, "held-open"), FileMode.CreateNew, FileAccess.Write, FileShare.None);   // e.g. a scanner holds a copy
        });
        try
        {
            var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), progress, Now);

            var work = Path.Combine(r.CaseFolder, "work");
            Assert.True(Directory.Exists(work));
            Assert.Contains(r.Scan.Warnings, w => w.Contains(work, StringComparison.OrdinalIgnoreCase) && w.Contains("could not be deleted"));
            Assert.Contains(work, File.ReadAllText(r.ReportPath).Replace(@"\\", @"\"), StringComparison.OrdinalIgnoreCase);
            Assert.Equal(PCPorter.Core.Cli.ExitCodes.Partial, HistoryJob.ExitCode(r));
        }
        finally { held?.Dispose(); }
    }

    [Fact]
    public void The_scanned_pcs_time_zone_comes_from_its_system_hive_offline_and_from_this_pc_live()
    {
        var system = RegSpec.Root().Key("Select", k => k.Num("Current", 1))
            .Key(@"ControlSet001\Control\TimeZoneInformation", k => k.Str("TimeZoneKeyName", "Tokyo Standard Time"));
        using var tokyo = new FakeSystemSource(_drive, system: system, users: [Bob]);
        var r = HistoryJob.Run(_out, tokyo, new HistoryJobOptions(), now: Now);
        Assert.Equal(("Tokyo Standard Time", "Asia/Tokyo"), (r.Scan.TimeZone.WindowsId, r.Scan.TimeZone.Iana));
        Assert.Contains("\"pcTimeZone\":{\"windowsId\":\"Tokyo Standard Time\",\"iana\":\"Asia/Tokyo\"", File.ReadAllText(r.ReportPath));

        using var noHive = new FakeSystemSource(_drive, users: [Bob]);
        Assert.Equal(PcTimeZone.Unknown, HistoryJob.Run(_out, noHive, new HistoryJobOptions(), now: Now).Scan.TimeZone);

        using var live = new FakeSystemSource(_drive, system: system, users: [Bob], live: true);
        var mine = HistoryJob.Run(_out, live, new HistoryJobOptions(CurrentUserSid: Bob.Sid, RestorePoints: false, Elevated: false), now: Now);
        Assert.Equal(TimeZoneInfo.Local.Id, mine.Scan.TimeZone.WindowsId);
    }

    [Fact]
    public void Bookmarks_tabs_and_form_entries_reach_the_report_and_secrets_reach_nothing()
    {
        using var source = Source();
        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);

        Assert.Equal(["https://firefox.example/", "https://tea.example/"], r.Scan.Bookmarks.Select(b => b.Url));
        Assert.Equal(["https://open.example/"], r.Scan.Tabs.Select(t => t.Url));
        Assert.Equal(["bob@example.com"], r.Scan.Forms.Select(f => f.Value));
        var html = File.ReadAllText(r.ReportPath);
        Assert.Contains("https://tea.example/", html);
        Assert.Contains("https://open.example/", html);
        Assert.Contains("bob@example.com", html);
        foreach (var file in Directory.EnumerateFiles(r.CaseFolder, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain(Canary, System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(file)));
    }

    [Fact]
    public void Summary_and_exit_code_report_counts_and_partial_runs()
    {
        using var source = Source();
        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);
        var s = HistoryJob.Summarize(r);
        Assert.Equal((3, 5, 2, 1, 0), (s.Profiles, s.Visits, s.Searches, s.Downloads, s.Recovered));
        Assert.Equal((2, 1, 1), (s.Bookmarks, s.Tabs, s.Forms));
        Assert.True(s.Warnings >= 1);
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Partial, HistoryJob.ExitCode(r));

        var clean = r with { Scan = r.Scan with { Warnings = [] }, FolderWarnings = [] };
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Ok, HistoryJob.ExitCode(clean));
    }

    [Fact]
    public void Deleted_visits_reach_the_report_and_case_rows_marked_as_recovered()
    {
        var bob = Path.Combine(_drive, "Users", "bob");
        ChromeHistory(Path.Combine(bob, @"AppData\Local\Google\Chrome\User Data\Default"), c =>
        {
            Sql(c, "PRAGMA secure_delete=OFF");
            for (int i = 1; i <= 6; i++)
            {
                Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES ({i}, 'https://site{i}.example/page', 'Site {i}', {WebKit(T0.AddMinutes(i))})");
                Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES ({i}, {WebKit(T0.AddMinutes(i))}, {0x30000001})");
            }
            Sql(c, "DELETE FROM visits WHERE url IN (2, 3); DELETE FROM urls WHERE id IN (2, 3);");
        });
        using var source = new FakeSystemSource(_drive, users: [new UserProfile("S-1-5-21-1-2-3-1001", "bob", bob, null, @"C:\Users\bob")]);

        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);

        var recovered = r.Scan.Visits.Where(v => v.Origin == Origin.Carved).ToList();
        Assert.Equal(["https://site2.example/page", "https://site3.example/page"], recovered.Select(v => v.Url));
        Assert.Equal([T0.AddMinutes(2), T0.AddMinutes(3)], recovered.Select(v => v.When));
        Assert.Equal(4, r.Scan.Coverage.Single().Visits);                // coverage is what the browser itself still keeps
        Assert.Equal(2, HistoryJob.Summarize(r).Recovered);
        Assert.Contains(r.Scan.Notes, n => n.Contains("2 visits were recovered from leftover data"));

        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var row = db.Search("site2.example").Single(a => a.Category == "WebHistory.Visit");
        Assert.Contains("\"Origin\":\"Carved\"", row.Detail);
        Assert.Contains("\"OriginNote\":\"free space\"", row.Detail);
        var live = db.Search("site1.example").Single(a => a.Category == "WebHistory.Visit");
        Assert.Contains("\"Origin\":\"Live\"", live.Detail);
        Assert.Contains("id=\"s-recovered\"", File.ReadAllText(r.ReportPath));
    }

    [Fact]
    public void Older_visits_from_restore_points_are_added_once_and_marked()
    {
        var bob = Path.Combine(_drive, "Users", "bob");
        const string rel = @"AppData\Local\Google\Chrome\User Data\Default";
        ChromeHistory(Path.Combine(bob, rel), c =>
        {
            Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES (1, 'https://now.example/', 'Now', {WebKit(T0)})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (1, {WebKit(T0)}, {0x30000001})");
        });
        var copy = Path.Combine(_out, "restore-point-copy");          // stands in for a shadow copy device
        ChromeHistory(Path.Combine(copy, @"Users\bob", rel), c =>
        {
            Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES (1, 'https://now.example/', 'Now', {WebKit(T0)})");
            Sql(c, $"INSERT INTO urls(id, url, title, last_visit_time) VALUES (2, 'https://old.example/', 'Old', {WebKit(T0.AddDays(-50))})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (1, {WebKit(T0)}, {0x30000001})");
            Sql(c, $"INSERT INTO visits(url, visit_time, transition) VALUES (2, {WebKit(T0.AddDays(-50))}, {0x30000000})");
        });
        var root = new RestorePointRoot(copy, new DateTimeOffset(2026, 1, 20, 4, 0, 0, TimeSpan.Zero),
            p => p.StartsWith(_drive, StringComparison.OrdinalIgnoreCase) ? copy + p[_drive.Length..] : null);
        using var source = new FakeSystemSource(_drive, users: [new UserProfile("S-1-5-21-1-2-3-1001", "bob", bob, null, @"C:\Users\bob")]);

        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(RestorePointRoots: [root]), now: Now);

        var old = Assert.Single(r.Scan.Visits, v => v.Origin == Origin.RestorePoint);
        Assert.Equal(("https://old.example/", T0.AddDays(-50)), (old.Url, old.When));
        Assert.Equal($"restore point {TimeZoneInfo.ConvertTime(root.Created, TimeZoneInfo.Local):yyyy-MM-dd HH:mm}, no longer in the browser's history", old.OriginNote);
        Assert.Equal(2, r.Scan.Visits.Count);
        Assert.Equal(1, r.Scan.Coverage.Single().Visits);
        Assert.Equal(1, HistoryJob.Summarize(r).Recovered);
        Assert.Contains(r.Scan.Notes, n => n.Contains("1 restore point was searched"));
        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        Assert.Contains("\"Origin\":\"RestorePoint\"", db.Search("old.example").Single(a => a.Category == "WebHistory.Visit").Detail);

        // Without the hook an offline drive has no restore points of its own: a note; turned off: nothing at all.
        var offline = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);
        Assert.Contains(offline.Scan.Notes, n => n.Contains("restore points were not searched", StringComparison.OrdinalIgnoreCase) || n.Contains("Restore points belong to the running PC"));
        Assert.DoesNotContain(offline.Scan.Visits, v => v.Origin == Origin.RestorePoint);
        var off = HistoryJob.Run(_out, source, new HistoryJobOptions(RestorePoints: false, RestorePointRoots: [root]), now: Now);
        Assert.DoesNotContain(off.Scan.Visits, v => v.Origin == Origin.RestorePoint);
        Assert.DoesNotContain(off.Scan.Notes, n => n.Contains("restore point", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Live_runs_read_only_the_current_account_unless_all_users_is_set()
    {
        using var offline = Source();
        using var live = new FakeSystemSource(_drive, users: offline.Users, live: true);

        var mine = HistoryJob.Run(_out, live, new HistoryJobOptions(CurrentUserSid: "S-1-5-21-1-2-3-1002"), now: Now);
        Assert.Empty(mine.Scan.Visits);                               // carol only, and her profile is unavailable

        var all = HistoryJob.Run(_out, live, new HistoryJobOptions(AllUsers: true, CurrentUserSid: "S-1-5-21-1-2-3-1002"), now: Now);
        Assert.Equal(5, all.Scan.Visits.Count);
    }

    const string WebCacheRel = @"AppData\Local\Microsoft\Windows\WebCache";
    const string Ie = "Internet Explorer / Edge (legacy)";

    /// <summary>bob's WebCacheV01.dat under <paramref name="root"/>: one visit, one search and one download.</summary>
    static void IeCache(string root) => WebCacheFixture.Create(Path.Combine(root, @"Users\bob", WebCacheRel),
        new WebCacheFixture.Container(1, "History",
        [
            new WebCacheFixture.Entry("Visited: bob@https://ie.example/", T0),
            new WebCacheFixture.Entry("Visited: bob@https://www.bing.com/search?q=ie+tea", T0.AddMinutes(1)),
        ]),
        new WebCacheFixture.Container(2, "iedownload",
        [
            new WebCacheFixture.Entry("iedownload:https://ie.example/setup.exe", T0.AddMinutes(2),
                ResponseHeaders: WebCacheFixture.DownloadHeaders("https://ie.example/setup.exe", "https://ie.example/", @"C:\Users\bob\Downloads\setup.exe")),
        ]));

    UserProfile Bob => new("S-1-5-21-1-2-3-1001", "bob", Path.Combine(_drive, "Users", "bob"), null, @"C:\Users\bob");

    [Fact]
    public void Offline_drives_read_internet_explorer_history_directly()
    {
        IeCache(_drive);
        using var source = new FakeSystemSource(_drive, users: [Bob]);

        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);

        Assert.Empty(r.Scan.Warnings);
        Assert.Equal(["https://ie.example/", "https://www.bing.com/search?q=ie+tea"], r.Scan.Visits.Select(v => v.Url));
        Assert.Equal(["ie tea"], r.Scan.Searches.Select(s => s.Terms));
        Assert.Equal(@"C:\Users\bob\Downloads\setup.exe", Assert.Single(r.Scan.Downloads).TargetPath);
        var coverage = Assert.Single(r.Scan.Coverage);
        Assert.Equal((Ie, 2, T0), (coverage.Profile.Browser, coverage.Visits, coverage.Earliest));
        Assert.Contains("Internet Explorer keeps", coverage.Note);
        Assert.DoesNotContain(r.Scan.Notes, n => n.Contains("needs administrator"));
        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        Assert.Equal($"{Ie}/Default", db.Search("ie.example").First(a => a.Category == "WebHistory.Visit").Source);
    }

    [Fact]
    public void Live_runs_without_administrator_rights_leave_a_note_and_take_no_shadow_copy()
    {
        IeCache(_drive);
        var snapshots = new FakeSnapshots(_drive, _drive);
        using var source = new FakeSystemSource(_drive, users: [Bob], live: true);

        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(CurrentUserSid: Bob.Sid, RestorePoints: false, Elevated: false, Snapshots: snapshots), now: Now);

        Assert.Empty(r.Scan.Visits);
        Assert.Contains(r.Scan.Notes, n => n.Contains("Internet Explorer / legacy Edge history needs administrator"));
        Assert.Equal(0, snapshots.Created);
    }

    [Fact]
    public void Live_runs_as_administrator_read_internet_explorer_history_from_a_temporary_shadow_copy()
    {
        var shadow = Path.Combine(_out, "shadow");                     // stands in for the shadow copy device
        IeCache(shadow);
        Directory.CreateDirectory(Path.Combine(_drive, @"Users\bob", WebCacheRel));
        File.WriteAllBytes(Path.Combine(_drive, @"Users\bob", WebCacheRel, "WebCacheV01.dat"), [0]);    // the live file is locked: never read
        var snapshots = new FakeSnapshots(_drive, shadow);
        using var source = new FakeSystemSource(_drive, users: [Bob], live: true);

        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(CurrentUserSid: Bob.Sid, RestorePoints: false, Elevated: true, Snapshots: snapshots), now: Now);

        Assert.Empty(r.Scan.Warnings);
        Assert.Equal(2, r.Scan.Visits.Count);
        Assert.Equal(Path.Combine(_drive, @"Users\bob", WebCacheRel), r.Scan.Visits[0].Profile.Folder);    // shown as on the PC
        Assert.Equal((1, 1), (snapshots.Created, snapshots.Disposed));

        // A shadow copy that cannot be made is a note, not a failed run.
        var failing = new FakeSnapshots(_drive, shadow) { Fail = true };
        var r2 = HistoryJob.Run(_out, source, new HistoryJobOptions(CurrentUserSid: Bob.Sid, RestorePoints: false, Elevated: true, Snapshots: failing), now: Now);
        Assert.Empty(r2.Scan.Visits);
        Assert.Contains(r2.Scan.Notes, n => n.Contains("Internet Explorer / legacy Edge history could not be read"));
    }

    /// <summary>A shadow copy provider whose "snapshot" maps the live drive folder onto another folder.</summary>
    sealed class FakeSnapshots(string liveRoot, string shadowRoot) : PCPorter.Core.Snapshots.ISnapshotProvider
    {
        public int Created, Disposed;
        public bool Fail;

        public PCPorter.Core.Snapshots.ISnapshot Create(string volumeRoot)
        {
            if (Fail) throw new InvalidOperationException("Windows could not create a shadow copy of C:\\ (code 1: access denied).");
            Created++;
            return new Snap(this, liveRoot, shadowRoot);
        }

        sealed class Snap(FakeSnapshots owner, string liveRoot, string shadowRoot) : PCPorter.Core.Snapshots.ISnapshot
        {
            public string DeviceRoot => shadowRoot;
            public string Map(string livePath) => livePath.StartsWith(liveRoot, StringComparison.OrdinalIgnoreCase)
                ? shadowRoot + livePath[liveRoot.Length..]
                : throw new ArgumentException($"{livePath} is not on the snapshot volume.");
            public void Dispose() => owner.Disposed++;
        }
    }
}
