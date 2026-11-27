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

        Assert.Equal(3, r.Scan.Visits.Count);
        Assert.Equal(["tea"], r.Scan.Searches.Select(s => s.Terms));
        var download = Assert.Single(r.Scan.Downloads);
        Assert.True(download.StillOnDisk);
        Assert.Equal(["Google Chrome", "Microsoft Edge"], r.Scan.Coverage.Select(c => c.Profile.Browser));
        Assert.Equal(3, r.Scan.Coverage[0].Visits);
        Assert.Equal(T0, r.Scan.Coverage[0].Earliest);
        Assert.Contains(r.Scan.Warnings, w => w.Contains("Microsoft Edge") && w.Contains("bob"));
        Assert.Contains(r.Scan.Notes, n => n.Contains("carol"));

        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var counts = db.CountByCategory();
        Assert.Equal(3, counts["WebHistory.Visit"]);
        Assert.Equal(1, counts["WebHistory.Search"]);
        Assert.Equal(1, counts["WebHistory.Download"]);
        Assert.Equal(1, counts["WebHistory.Bookmark"]);
        Assert.Equal(1, counts["WebHistory.Tab"]);
        Assert.Equal(1, counts["WebHistory.Form"]);
        var visit = db.Search("example.com").First(a => a.Category == "WebHistory.Visit");
        Assert.Equal("Google Chrome/Default", visit.Source);
        Assert.Equal("bob", visit.User);
    }

    [Fact]
    public void Bookmarks_tabs_and_form_entries_reach_the_report_and_secrets_reach_nothing()
    {
        using var source = Source();
        var r = HistoryJob.Run(_out, source, new HistoryJobOptions(), now: Now);

        Assert.Equal(["https://tea.example/"], r.Scan.Bookmarks.Select(b => b.Url));
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
        Assert.Equal((2, 3, 1, 1, 0), (s.Profiles, s.Visits, s.Searches, s.Downloads, s.Recovered));
        Assert.True(s.Warnings >= 1);
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Partial, HistoryJob.ExitCode(r));

        var clean = r with { Scan = r.Scan with { Warnings = [] }, FolderWarnings = [] };
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Ok, HistoryJob.ExitCode(clean));
    }

    [Fact]
    public void Live_runs_read_only_the_current_account_unless_all_users_is_set()
    {
        using var offline = Source();
        using var live = new FakeSystemSource(_drive, users: offline.Users, live: true);

        var mine = HistoryJob.Run(_out, live, new HistoryJobOptions(CurrentUserSid: "S-1-5-21-1-2-3-1002"), now: Now);
        Assert.Empty(mine.Scan.Visits);                               // carol only, and her profile is unavailable

        var all = HistoryJob.Run(_out, live, new HistoryJobOptions(AllUsers: true, CurrentUserSid: "S-1-5-21-1-2-3-1002"), now: Now);
        Assert.Equal(3, all.Scan.Visits.Count);
    }
}
