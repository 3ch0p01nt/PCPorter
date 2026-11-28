using Microsoft.Data.Sqlite;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.Forensics.SearchIndex;
using PCPorter.TestKit;
using static PCPorter.TestKit.ChromiumFixture;

namespace PCPorter.Forensics.Tests.BrowserHistory;

/// <summary>
/// Databases from an infected old drive whose schema is hostile: the tables the readers name are views that join
/// themselves six ways (a trillion rows), return zeroblob(1e9), or are virtual tables. Each must finish quickly with a
/// warning and nothing read from that table.
/// </summary>
public class UntrustedDatabaseTests : IDisposable
{
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    static readonly TimeSpan Quick = TimeSpan.FromSeconds(5);

    readonly string _dir = BrowserFixtures.TempDir();
    string Work => Directory.CreateDirectory(Path.Combine(_dir, "work")).FullName;
    public void Dispose() => BrowserFixtures.Delete(_dir);

    /// <summary>A 100-row table n(x) and a view over six copies of it.</summary>
    static string CrossJoinView(string name, string columns) => $"""
        CREATE TABLE n(x);
        WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c LIMIT 100) INSERT INTO n SELECT i FROM c;
        CREATE VIEW {name} AS SELECT {columns} FROM n a, n b, n c, n d, n e, n f;
        """;

    const string ChromiumUrlColumns = "a.x AS id, 'https://evil.example/' AS url, 'Evil' AS title, 0 AS visit_count, 0 AS typed_count, 0 AS last_visit_time, 0 AS hidden";

    ProfileHistory ReadChromium(string hostileSql, out TimeSpan cpu)
    {
        var folder = Path.Combine(_dir, "Default");
        var profile = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", folder);
        using (var f = new ChromiumFixture(folder))
        {
            f.Visit(f.Url("https://example.com/", "Example"), T0, ChainStart | ChainEnd | 1);
            f.Sql(hostileSql);
        }
        ProfileHistory? h = null;
        var work = Work;
        cpu = ThreadCpu.Of(() => h = ChromiumHistoryReader.Read(profile, work));
        return h ?? throw new TimeoutException("the read did not finish");
    }

    [Fact]
    public void A_history_whose_urls_is_a_six_way_cross_join_view_finishes_quickly_with_a_warning()
    {
        var h = ReadChromium("DROP TABLE urls;" + CrossJoinView("urls", ChromiumUrlColumns), out var cpu);
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
        Assert.Contains(h.Warnings, w => w.Contains("\"urls\" table is a view"));
        Assert.DoesNotContain(h.Visits, v => v.Url.Contains("evil.example"));
    }

    [Fact]
    public void A_history_whose_urls_returns_a_gigabyte_blob_finishes_quickly_with_a_warning()
    {
        var h = ReadChromium("""
            DROP TABLE urls;
            CREATE VIEW urls AS SELECT 1 AS id, zeroblob(1000000000) AS url, 'x' AS title, 0 AS visit_count, 0 AS typed_count, 0 AS last_visit_time, 0 AS hidden;
            """, out var cpu);
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
        Assert.Contains(h.Warnings, w => w.Contains("\"urls\" table is a view"));
    }

    [Fact]
    public void A_history_whose_urls_is_a_virtual_table_is_refused_with_a_warning()
    {
        var h = ReadChromium("""
            DROP TABLE urls;
            CREATE VIRTUAL TABLE urls USING fts4(id, url, title, visit_count, typed_count, last_visit_time, hidden);
            INSERT INTO urls VALUES (1, 'https://evil.example/', 'Evil', 0, 0, 0, 0);
            """, out _);
        Assert.Contains(h.Warnings, w => w.Contains("\"urls\" table is a virtual table"));
        Assert.DoesNotContain(h.Visits, v => v.Url.Contains("evil.example"));
    }

    [Fact]
    public void A_downloads_view_is_skipped_but_the_visits_are_still_read()
    {
        var h = ReadChromium("DROP TABLE downloads;" + CrossJoinView("downloads", "a.x AS id, 'https://evil.example/' AS tab_url, 0 AS start_time"), out var cpu);
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
        Assert.Contains(h.Warnings, w => w.Contains("\"downloads\" table is a view"));
        Assert.Empty(h.Downloads);
        Assert.Contains(h.Visits, v => v.Url == "https://example.com/");
    }

    [Fact]
    public void A_web_data_whose_autofill_is_a_view_is_not_read()
    {
        var folder = Path.Combine(_dir, "Default");
        WebDataFixture.Create(folder, ("email", "bob@example.com", 1, 0, 0));
        using (var c = new SqliteConnection($"Data Source={Path.Combine(folder, "Web Data")};Pooling=False"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "DROP TABLE autofill;" + CrossJoinView("autofill", "'f' AS name, 'v' AS value, 1 AS count, 0 AS date_created, 0 AS date_last_used");
            cmd.ExecuteNonQuery();
        }
        var profile = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", folder);
        var work = Work;
        var cpu = ThreadCpu.Of(() => Assert.Throws<InvalidDataException>(() => ChromiumWebData.Read(profile, work, [])));
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
    }

    [Fact]
    public void A_firefox_profile_whose_places_is_a_cross_join_view_finishes_quickly_with_a_warning()
    {
        var folder = Path.Combine(_dir, "ff");
        using (var f = new FirefoxFixture(folder))
        {
            f.Visit(f.Place("https://example.com/", "Example"), T0, 1);
            f.Sql("DROP TABLE moz_places;" + CrossJoinView("moz_places",
                "a.x AS id, 'https://evil.example/' AS url, 'Evil' AS title, '' AS rev_host, 0 AS visit_count, 0 AS hidden, 0 AS typed, 0 AS frecency, 0 AS last_visit_date, 'g' AS guid, 0 AS foreign_count, 0 AS url_hash"));
        }
        var profile = new BrowserProfile("bob", "Firefox", BrowserFamily.Firefox, "default", folder);
        ProfileHistory? h = null;
        var work = Work;
        var cpu = ThreadCpu.Of(() => h = FirefoxHistoryReader.Read(profile, work));
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
        Assert.NotNull(h);
        Assert.Contains(h.Warnings, w => w.Contains("\"moz_places\" table is a view"));
        Assert.DoesNotContain(h.Visits, v => v.Url.Contains("evil.example"));
    }

    // ---------------------------------------------------------------- Windows 11 search index (Windows.db)

    string SearchIndex(string? hostileSql)
    {
        var path = Path.Combine(_dir, "Windows.db");
        using var c = new SqliteConnection($"Data Source={path};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE SystemIndex_1_PropertyStore_Metadata(Id INTEGER PRIMARY KEY, Name TEXT);
            INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (1, 'System.ThumbnailCacheId'), (2, 'System.ItemPathDisplay');
            CREATE TABLE SystemIndex_1_PropertyStore(WorkId INTEGER, ColumnId INTEGER, Value, PRIMARY KEY (WorkId, ColumnId));
            INSERT INTO SystemIndex_1_PropertyStore VALUES (7, 1, x'1122334455667788'), (7, 2, 'C:\Users\bob\Pictures\cat.jpg');
            """ + (hostileSql ?? "");
        cmd.ExecuteNonQuery();
        return path;
    }

    [Fact]
    public void The_search_index_still_resolves_paths()
    {
        var resolver = new SearchIndexPathResolver(SearchIndex(null));
        var map = resolver.Resolve([0x8877665544332211UL]);
        Assert.True(map.TryGetValue(0x8877665544332211UL, out var path), string.Join(" | ", resolver.Notes));
        Assert.Equal(@"C:\Users\bob\Pictures\cat.jpg", path);
    }

    [Fact]
    public void A_search_index_whose_property_store_is_a_cross_join_view_finishes_quickly_with_a_note()
    {
        var resolver = new SearchIndexPathResolver(SearchIndex("DROP TABLE SystemIndex_1_PropertyStore;" +
            CrossJoinView("SystemIndex_1_PropertyStore", "a.x AS WorkId, 1 AS ColumnId, x'1122334455667788' AS Value")));
        IReadOnlyDictionary<ulong, string>? map = null;
        var cpu = ThreadCpu.Of(() => map = resolver.Resolve([0x8877665544332211UL]));
        Assert.True(cpu < Quick, $"{cpu.TotalSeconds:0.0} s of processor time");
        Assert.NotNull(map);
        Assert.Empty(map);
        Assert.Contains(resolver.Notes, n => n.Contains("is a view"));
    }
}
