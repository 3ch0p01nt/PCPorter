using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Forensics.Tests.BrowserHistory;

/// <summary>Chromium bookmarks, saved form entries (Web Data autofill) and session files.</summary>
public class ChromiumExtrasTests
{
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    static readonly BrowserProfile Profile = new("bob", "Google Chrome", BrowserFamily.Chromium, "Default", @"C:\nowhere");

    // ---- Bookmarks ----

    [Fact]
    public void Bookmarks_are_read_with_their_folder_path_and_time_added()
    {
        var json = """
            {"checksum":"x","roots":{
              "bookmark_bar":{"type":"folder","name":"Bookmarks bar","children":[
                {"type":"url","name":"Example","url":"https://example.com/","date_added":"T_ZERO"},
                {"type":"folder","name":"Work","children":[
                  {"type":"folder","name":"Admin","children":[
                    {"type":"url","name":"Router","url":"http://admin:hunter2@192.168.1.1/","date_added":"T_ONE"}]}]}]},
              "other":{"type":"folder","name":"Other bookmarks","children":[
                {"type":"url","name":"No date","url":"https://news.example.org/","date_added":"garbage"},
                {"type":"url","name":"No address"},
                {"type":"weird","name":"x","url":"https://ignored.example/"}]},
              "synced":{"type":"folder","name":"Mobile bookmarks","children":[]}},
             "version":1}
            """.Replace("T_ZERO", BrowserFixtures.WebKit(T0).ToString()).Replace("T_ONE", BrowserFixtures.WebKit(T0.AddDays(1)).ToString());

        var list = ChromiumBookmarks.Parse(Profile, Encoding.UTF8.GetBytes(json));

        Assert.Equal(
        [
            new Bookmark(Profile, "Example", "https://example.com/", "Bookmarks bar", T0),
            new Bookmark(Profile, "Router", "http://admin:***@192.168.1.1/", "Bookmarks bar/Work/Admin", T0.AddDays(1)),
            new Bookmark(Profile, "No date", "https://news.example.org/", "Other bookmarks", null),
        ], list);
    }

    [Fact]
    public void Bookmarks_file_with_a_byte_order_mark_and_no_roots_gives_nothing()
    {
        Assert.Empty(ChromiumBookmarks.Parse(Profile, (byte[])[0xEF, 0xBB, 0xBF, .. "{\"version\":1}"u8]));
        Assert.Empty(ChromiumBookmarks.Parse(Profile, "[]"u8.ToArray()));
    }

    // ---- Web Data (autofill only) ----

    [Fact]
    public void Form_entries_come_only_from_autofill_with_sensitive_fields_dropped_and_values_masked()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            var profile = Profile with { Folder = folder };
            long t = T0.ToUnixTimeSeconds();
            WebDataFixture.Create(folder,
                ("email", "bob@example.com", 4, t, t + 60),
                ("search", "api_key=abc123", 1, t, t + 120),
                ("password", WebDataFixture.Canary, 9, t, t),
                ("new-pwd", WebDataFixture.Canary, 1, t, t),
                ("cardnumber", WebDataFixture.Canary, 1, t, t),
                ("cc-num", WebDataFixture.Canary, 1, t, t),
                ("cvc", WebDataFixture.Canary, 1, t, t),
                ("Account_No", WebDataFixture.Canary, 1, t, t),
                ("note", "4111 1111 1111 1111", 1, t, t),        // a card number in an innocent-looking field
                ("phone", "0123456789", 2, 0, 0));
            var notes = new List<string>();

            var forms = ChromiumWebData.Read(profile, Path.Combine(dir, "work"), notes);

            Assert.Equal(
            [
                new FormEntry(profile, "search", "api_key=***", 1, T0, T0.AddMinutes(2)),
                new FormEntry(profile, "email", "bob@example.com", 4, T0, T0.AddMinutes(1)),
                new FormEntry(profile, "phone", "0123456789", 2, null, null),
            ], forms);
            Assert.Contains(notes, n => n.StartsWith("7 saved form entries", StringComparison.Ordinal));
            var everything = JsonSerializer.Serialize(new { forms, notes });
            Assert.DoesNotContain(WebDataFixture.Canary, everything);
            Assert.Empty(Directory.GetDirectories(Path.Combine(dir, "work")));     // the copy is removed
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void The_web_data_query_names_only_the_autofill_table()
    {
        var tables = System.Text.RegularExpressions.Regex.Matches(ChromiumWebData.AutofillSql, @"(?i)\b(?:FROM|JOIN)\s+(\w+)")
            .Select(m => m.Groups[1].Value).ToList();
        Assert.Equal(["autofill"], tables);
    }

    [Fact]
    public void The_read_guard_refuses_every_table_but_the_allowed_one()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            WebDataFixture.Create(dir, ("email", "bob@example.com", 1, 0, 0));
            using var conn = new SqliteConnection($"Data Source={Path.Combine(dir, "Web Data")};Pooling=False");
            conn.Open();
            SqliteReadGuard.AllowOnly(conn, "autofill");

            using var ok = conn.CreateCommand();
            ok.CommandText = ChromiumWebData.AutofillSql;
            using (var r = ok.ExecuteReader()) Assert.True(r.Read());

            foreach (var sql in new[]
            {
                "SELECT * FROM credit_cards", "SELECT nickname FROM masked_credit_cards", "SELECT value_encrypted FROM local_ibans",
                "SELECT label FROM autofill_profiles", "SELECT a.name FROM autofill a JOIN credit_cards c ON 1", "SELECT sql FROM sqlite_master",
                "DELETE FROM autofill", "ATTACH 'x.db' AS x", "PRAGMA table_info(credit_cards)",
            })
            {
                using var bad = conn.CreateCommand();
                bad.CommandText = sql;
                Assert.Throws<SqliteException>(() => { using var r = bad.ExecuteReader(); while (r.Read()) { } });
            }
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Theory]
    [InlineData("password", true)]
    [InlineData("user_pass", true)]
    [InlineData("pwd", true)]
    [InlineData("credit-card", true)]
    [InlineData("cc-number", true)]
    [InlineData("ccnum", true)]
    [InlineData("CVV2", true)]
    [InlineData("pin", true)]
    [InlineData("ssn", true)]
    [InlineData("iban", true)]
    [InlineData("accountNumber", true)]
    [InlineData("routing", true)]
    [InlineData("client_secret", true)]
    [InlineData("csrf_token", true)]
    [InlineData("otp_code", true)]
    [InlineData("email", false)]
    [InlineData("q", false)]
    [InlineData("firstname", false)]
    public void Sensitive_field_names(string field, bool sensitive) => Assert.Equal(sensitive, FormFields.IsSensitiveField(field));

    [Theory]
    [InlineData("4111111111111111", true)]
    [InlineData("4111-1111-1111-1111", true)]
    [InlineData("4111111111111112", false)]          // fails the Luhn check
    [InlineData("0123456789", false)]                // too short
    [InlineData("41111111111111111111", false)]      // too long
    [InlineData("hello", false)]
    public void Card_numbers_are_recognised(string value, bool card) => Assert.Equal(card, FormFields.LooksLikeCardNumber(value));

    // ---- Sessions (SNSS) ----

    [Fact]
    public void Session_file_gives_open_tabs_and_recently_closed_tabs_and_windows()
    {
        var file = new SnssBuilder()
            .TabWindow(100, 1).Navigation(1, 0, "https://example.com/", "Example").Navigation(1, 1, "https://example.com/next", "Next")
            .Selected(1, 1).LastActive(1, T0)
            .TabWindow(100, 2).Navigation(2, 0, "https://mail.example.org/?token=abc", "Mail").Selected(2, 0)
            .Command(99, [1, 2, 3])                                                         // unknown: skipped
            .TabWindow(100, 3).Navigation(3, 0, "https://closed.example/", "").TabClosed(3, T0.AddMinutes(5))
            .TabWindow(200, 4).Navigation(4, 0, "https://w2.example/a", "A").Navigation(4, 1, "https://w2.example/b", "B").Selected(4, 0)
            .WindowClosed(200, T0.AddMinutes(9))
            .TabWindow(100, 5)                                                              // no navigation: not a tab to show
            .Bytes();
        var notes = new List<string>();

        var tabs = ChromiumSessions.Parse(Profile, file, restoreList: false, notes);

        Assert.Equal(
        [
            new OpenTab(Profile, "https://example.com/next", "Next", 1, TabState.Open, T0),
            new OpenTab(Profile, "https://mail.example.org/?token=***", "Mail", 1, TabState.Open, null),
            new OpenTab(Profile, "https://closed.example/", null, 1, TabState.RecentlyClosed, T0.AddMinutes(5)),
            new OpenTab(Profile, "https://w2.example/a", "A", 2, TabState.RecentlyClosed, T0.AddMinutes(9)),
        ], tabs);
        Assert.Empty(notes);
    }

    [Fact]
    public void A_truncated_session_file_keeps_the_tabs_before_the_cut_and_says_so()
    {
        var file = new SnssBuilder(version: 3)
            .TabWindow(1, 7).Navigation(7, 0, "https://before.example/", "Before")
            .Raw(200, 0, 6, 1, 2, 3)                                                       // promises 200 bytes, holds 4
            .Bytes();
        var notes = new List<string>();

        var tabs = ChromiumSessions.Parse(Profile, file, restoreList: false, notes);

        Assert.Equal([new OpenTab(Profile, "https://before.example/", "Before", 1, TabState.Open, null)], tabs);
        Assert.Contains(notes, n => n.Contains("part-way through a record"));
    }

    [Fact]
    public void A_navigation_whose_strings_overrun_the_record_is_ignored()
    {
        var bad = new byte[] { 40, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0 };   // url length 65535 in a 16-byte record
        var file = new SnssBuilder().Command(6, bad).Navigation(2, 0, "https://ok.example/", "OK").Bytes();
        var tabs = ChromiumSessions.Parse(Profile, file, restoreList: false, []);
        Assert.Equal(["https://ok.example/"], tabs.Select(t => t.Url));
    }

    [Theory]
    [InlineData(new byte[] { 0x53, 0x4E })]                                                  // too short
    [InlineData(new byte[] { 0x4E, 0x4F, 0x50, 0x45, 1, 0, 0, 0 })]                          // wrong magic
    [InlineData(new byte[] { 0x53, 0x4E, 0x53, 0x53, 2, 0, 0, 0 })]                          // encrypted format
    public void Unreadable_session_files_give_a_note_not_an_exception(byte[] file)
    {
        var notes = new List<string>();
        Assert.Empty(ChromiumSessions.Parse(Profile, file, restoreList: false, notes));
        Assert.Single(notes);
    }

    [Fact]
    public void Tabs_file_lists_recently_closed_tabs()
    {
        var file = new SnssBuilder()
            .Navigation(11, 0, "https://one.example/", "One", id: 1).Navigation(11, 1, "https://two.example/", "Two", id: 1)
            .RestoreSelected(11, 0, T0)
            .Navigation(12, 0, "https://three.example/", "Three", id: 1)
            .Command(6, [0, 0, 0, 0])                                                       // a restore-file command PCPorter does not use
            .Bytes();

        var tabs = ChromiumSessions.Parse(Profile, file, restoreList: true, []);

        Assert.Equal(
        [
            new OpenTab(Profile, "https://one.example/", "One", 0, TabState.RecentlyClosed, T0),
            new OpenTab(Profile, "https://three.example/", "Three", 0, TabState.RecentlyClosed, null),
        ], tabs);
    }

    [Fact]
    public void Only_the_newest_session_and_tabs_files_are_read()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var sessions = Path.Combine(dir, "Sessions");
            Directory.CreateDirectory(sessions);
            File.WriteAllBytes(Path.Combine(sessions, "Session_13350000000000000"), new SnssBuilder().Navigation(1, 0, "https://old.example/", "Old").Bytes());
            File.WriteAllBytes(Path.Combine(sessions, "Session_13360000000000000"), new SnssBuilder().Navigation(1, 0, "https://new.example/", "New").Bytes());
            File.WriteAllBytes(Path.Combine(sessions, "Tabs_13360000000000000"), new SnssBuilder().Navigation(5, 0, "https://gone.example/", "Gone", id: 1).Bytes());
            File.WriteAllBytes(Path.Combine(dir, "Current Session"), new SnssBuilder().Navigation(1, 0, "https://legacy.example/", "Legacy").Bytes());

            var tabs = ChromiumSessions.Read(Profile with { Folder = dir }, []);

            Assert.Equal([("https://new.example/", TabState.Open), ("https://gone.example/", TabState.RecentlyClosed)], tabs.Select(t => (t.Url, t.State)));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void A_session_file_locked_by_the_running_browser_falls_back_to_the_previous_one_with_a_note()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var sessions = Path.Combine(dir, "Sessions");
            Directory.CreateDirectory(sessions);
            var older = Path.Combine(sessions, "Session_13350000000000000");
            var newer = Path.Combine(sessions, "Session_13360000000000000");
            File.WriteAllBytes(older, new SnssBuilder().Navigation(1, 0, "https://previous.example/", "Previous").Bytes());
            File.WriteAllBytes(newer, new SnssBuilder().Navigation(1, 0, "https://current.example/", "Current").Bytes());
            var notes = new List<string>();

            List<OpenTab> tabs;
            using (new FileStream(newer, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                tabs = ChromiumSessions.Read(Profile with { Folder = dir }, notes);

            Assert.Equal(["https://previous.example/"], tabs.Select(t => t.Url));
            Assert.Contains(notes, n => n.Contains("in use by the running browser"));

            using (new FileStream(newer, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            using (new FileStream(older, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                Assert.ThrowsAny<IOException>(() => ChromiumSessions.Read(Profile with { Folder = dir }, []));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    // ---- The whole profile ----

    [Fact]
    public void Reading_a_profile_includes_bookmarks_tabs_and_forms_and_never_opens_secret_files()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            var profile = Profile with { Folder = folder };
            using (var f = new ChromiumFixture(folder))
                f.Visit(f.Url("https://example.com/", "Example"), T0, ChromiumFixture.ChainStart | ChromiumFixture.ChainEnd | 1);
            File.WriteAllText(Path.Combine(folder, "Bookmarks"), """{"roots":{"bookmark_bar":{"children":[{"type":"url","name":"E","url":"https://e.example/"}]}}}""");
            Directory.CreateDirectory(Path.Combine(folder, "Sessions"));
            File.WriteAllBytes(Path.Combine(folder, "Sessions", "Session_1"), new SnssBuilder().Navigation(1, 0, "https://tab.example/", "Tab").Bytes());
            WebDataFixture.Create(folder, ("email", "bob@example.com", 1, T0.ToUnixTimeSeconds(), T0.ToUnixTimeSeconds()));
            foreach (var bait in new[] { "Login Data", "Login Data For Account", "Cookies", @"Network\Cookies" })
                BrowserFixtures.Touch(folder, bait, WebDataFixture.Canary);
            var reads = new List<string>();

            ProfileHistory h;
            using (SourceFiles.Observe((kind, path) => { if (kind == "read") reads.Add(Path.GetFileName(path)); }))
                h = ChromiumHistoryReader.Read(profile, Path.Combine(dir, "work"));

            Assert.Single(h.Visits);
            Assert.Equal(["https://e.example/"], h.Bookmarks.Select(b => b.Url));
            Assert.Equal(["https://tab.example/"], h.Tabs.Select(t => t.Url));
            Assert.Equal(["bob@example.com"], h.Forms.Select(x => x.Value));
            Assert.Empty(h.Warnings);
            Assert.Equal(["Bookmarks", "History", "Session_1", "Web Data"], reads.Distinct().Order(StringComparer.Ordinal));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void A_damaged_bookmarks_file_is_a_warning_and_the_rest_of_the_profile_is_read()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder))
                f.Visit(f.Url("https://example.com/"), T0, ChromiumFixture.ChainStart | ChromiumFixture.ChainEnd | 1);
            File.WriteAllText(Path.Combine(folder, "Bookmarks"), "{\"roots\": {");

            var h = ChromiumHistoryReader.Read(Profile with { Folder = folder }, Path.Combine(dir, "work"));

            Assert.Single(h.Visits);
            Assert.Contains(h.Warnings, w => w.Contains("bookmarks could not be read"));
        }
        finally { BrowserFixtures.Delete(dir); }
    }
}
