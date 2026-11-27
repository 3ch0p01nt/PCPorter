using System.Text;

namespace PCPorter.Forensics.Tests.BrowserHistory;

/// <summary>Synthetic browser profile trees for the history tests. Nothing here comes from a real PC.</summary>
internal static class BrowserFixtures
{
    public static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "pcporter-history-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Delete(string dir)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Creates a file (and its folders) with some bytes.</summary>
    public static string Touch(string root, string relative, string content = "x")
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, Encoding.UTF8);
        return path;
    }

    /// <summary>Chromium "Local State" with display names for the given profile folders.</summary>
    public static string LocalState(params (string Dir, string Name)[] profiles)
    {
        var cache = string.Join(",", profiles.Select(p => $"\"{p.Dir}\":{{\"name\":\"{p.Name}\",\"avatar_icon\":\"x\"}}"));
        return "{\"os_crypt\":{\"encrypted_key\":\"not-a-real-key\"},\"profile\":{\"info_cache\":{" + cache + "}}}";
    }

    public static long WebKit(DateTimeOffset t) => t.UtcDateTime.ToFileTimeUtc() / 10;
}

/// <summary>
/// Builds a Chromium "History" database with the real schema (current Chrome: urls, visits, keyword_search_terms,
/// downloads, downloads_url_chains, meta). Transitions are stored the way Chrome stores them (signed 32-bit).
/// </summary>
internal sealed class ChromiumFixture : IDisposable
{
    public const string Schema = """
        CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,term LONGVARCHAR NOT NULL,normalized_term LONGVARCHAR NOT NULL);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,last_access_time INTEGER NOT NULL,transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,site_url VARCHAR NOT NULL,embedder_download_data VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,tab_referrer_url VARCHAR NOT NULL,http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,by_web_app_id VARCHAR NOT NULL,etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,original_mime_type VARCHAR(255) NOT NULL);
        CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));
        INSERT INTO meta VALUES ('version', '70');
        """;

    // Chromium page transition qualifiers.
    public const uint ChainStart = 0x10000000, ChainEnd = 0x20000000, ClientRedirect = 0x40000000, ServerRedirect = 0x80000000;

    readonly Microsoft.Data.Sqlite.SqliteConnection _conn;
    public string Path { get; }

    public ChromiumFixture(string profileFolder)
    {
        Directory.CreateDirectory(profileFolder);
        Path = System.IO.Path.Combine(profileFolder, "History");
        _conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path};Pooling=False");
        _conn.Open();
        Exec(Schema);
    }

    long Exec(string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
        cmd.CommandText = "SELECT last_insert_rowid()";
        cmd.Parameters.Clear();
        return (long)cmd.ExecuteScalar()!;
    }

    public long Url(string url, string? title = null, DateTimeOffset? lastVisit = null) =>
        Exec("INSERT INTO urls(url, title, last_visit_time) VALUES ($u, $t, $l)",
            ("$u", url), ("$t", title ?? ""), ("$l", lastVisit is { } l ? BrowserFixtures.WebKit(l) : 0L));

    public long Visit(long urlId, DateTimeOffset when, uint transition, long durationMicros = 0, long fromVisit = 0) =>
        Exec("INSERT INTO visits(url, visit_time, from_visit, transition, visit_duration) VALUES ($u, $t, $f, $tr, $d)",
            ("$u", urlId), ("$t", BrowserFixtures.WebKit(when)), ("$f", fromVisit), ("$tr", unchecked((int)transition)), ("$d", durationMicros));

    public void SearchTerm(long urlId, string term) =>
        Exec("INSERT INTO keyword_search_terms VALUES (2, $u, $t, $n)", ("$u", urlId), ("$t", term), ("$n", term.ToLowerInvariant()));

    public long Download(string target, DateTimeOffset start, long received, long total, int state, string referrer, string tabUrl, params string[] chain)
    {
        var id = Exec("""
            INSERT INTO downloads VALUES (NULL, 'guid', $p, $p, $s, $r, $t, $st, 0, 0, x'', $s, 0, 0, 0, $ref, '', '', $tab, '', 'GET', '', '', '', '', '', 'application/octet-stream', 'application/octet-stream')
            """, ("$p", target), ("$s", BrowserFixtures.WebKit(start)), ("$r", received), ("$t", total), ("$st", state), ("$ref", referrer), ("$tab", tabUrl));
        for (int i = 0; i < chain.Length; i++)
            Exec("INSERT INTO downloads_url_chains VALUES ($i, $c, $u)", ("$i", id), ("$c", i), ("$u", chain[i]));
        return id;
    }

    public void Dispose() => _conn.Dispose();
}
