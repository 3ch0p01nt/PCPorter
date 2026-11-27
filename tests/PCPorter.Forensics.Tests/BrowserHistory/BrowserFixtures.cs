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

/// <summary>Builds a Chromium SNSS session file (Session_* or Tabs_*) command by command.</summary>
internal sealed class SnssBuilder
{
    readonly MemoryStream _ms = new();

    public SnssBuilder(int version = 1)
    {
        _ms.Write("SNSS"u8);
        _ms.Write(BitConverter.GetBytes(version));
    }

    public SnssBuilder Command(byte id, byte[] payload)
    {
        _ms.Write(BitConverter.GetBytes(checked((ushort)(payload.Length + 1))));
        _ms.WriteByte(id);
        _ms.Write(payload);
        return this;
    }

    /// <summary>Raw bytes, e.g. a record header that promises more than the file holds.</summary>
    public SnssBuilder Raw(params byte[] bytes) { _ms.Write(bytes); return this; }

    public SnssBuilder Navigation(int tab, int index, string url, string title, byte id = 6) => Command(id, Pickle(tab, index, url, title));
    public SnssBuilder TabWindow(int window, int tab) => Command(0, Ints(window, tab));
    public SnssBuilder Selected(int tab, int index) => Command(7, Ints(tab, index));
    public SnssBuilder TabClosed(int tab, DateTimeOffset when) => Command(16, IdTime(tab, when));
    public SnssBuilder WindowClosed(int window, DateTimeOffset when) => Command(17, IdTime(window, when));
    public SnssBuilder LastActive(int tab, DateTimeOffset when) => Command(21, IdTime(tab, when));
    /// <summary>Tabs_ file: which navigation of a closed tab was showing, and when it was closed.</summary>
    public SnssBuilder RestoreSelected(int tab, int index, DateTimeOffset closed) =>
        Command(4, [.. BitConverter.GetBytes(tab), .. BitConverter.GetBytes(index), .. BitConverter.GetBytes(BrowserFixtures.WebKit(closed))]);

    public byte[] Bytes() => _ms.ToArray();

    static byte[] Ints(params int[] values) => values.SelectMany(BitConverter.GetBytes).ToArray();

    static byte[] IdTime(int id, DateTimeOffset when) => [.. BitConverter.GetBytes(id), 0, 0, 0, 0, .. BitConverter.GetBytes(BrowserFixtures.WebKit(when))];

    /// <summary>Pickle: uint32 payload size, int32 tab, int32 index, string url, string16 title, then more fields (here: an empty state).</summary>
    static byte[] Pickle(int tab, int index, string url, string title)
    {
        var body = new MemoryStream();
        void Pad() { while (body.Length % 4 != 0) body.WriteByte(0); }
        body.Write(BitConverter.GetBytes(tab));
        body.Write(BitConverter.GetBytes(index));
        var u = Encoding.UTF8.GetBytes(url);
        body.Write(BitConverter.GetBytes(u.Length)); body.Write(u); Pad();
        var t = Encoding.Unicode.GetBytes(title);
        body.Write(BitConverter.GetBytes(title.Length)); body.Write(t); Pad();
        body.Write(BitConverter.GetBytes(0));           // encoded page state: empty
        body.Write(BitConverter.GetBytes(0));           // transition type
        return [.. BitConverter.GetBytes((int)body.Length), .. body.ToArray()];
    }
}

/// <summary>Builds a Chromium "Web Data" database with the autofill table and the tables PCPorter must never read.</summary>
internal static class WebDataFixture
{
    public const string Canary = "CANARY-7f3a91";

    public static void Create(string profileFolder, params (string Name, string Value, int Count, long Created, long LastUsed)[] autofill)
    {
        Directory.CreateDirectory(profileFolder);
        using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(profileFolder, "Web Data")};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"""
            CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
            CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
            CREATE TABLE credit_cards ( guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '', use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR, nickname VARCHAR);
            CREATE TABLE masked_credit_cards (id VARCHAR, network VARCHAR, last_four VARCHAR, exp_month INTEGER DEFAULT 0, exp_year INTEGER DEFAULT 0, bank_name VARCHAR, nickname VARCHAR);
            CREATE TABLE local_ibans (guid VARCHAR, use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, value_encrypted VARCHAR, nickname VARCHAR);
            CREATE TABLE autofill_profiles (guid VARCHAR PRIMARY KEY, label VARCHAR, date_modified INTEGER NOT NULL DEFAULT 0);
            INSERT INTO meta VALUES ('version', '130');
            INSERT INTO credit_cards (guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, nickname) VALUES ('g1', '{Canary}', 1, 2030, CAST('{Canary}' AS BLOB), '{Canary}');
            INSERT INTO masked_credit_cards (id, network, last_four, nickname) VALUES ('m1', 'visa', '1111', '{Canary}');
            INSERT INTO local_ibans (guid, value_encrypted, nickname) VALUES ('i1', '{Canary}', '{Canary}');
            INSERT INTO autofill_profiles (guid, label) VALUES ('p1', '{Canary}');
            """;
        cmd.ExecuteNonQuery();
        foreach (var a in autofill)
        {
            cmd.CommandText = "INSERT INTO autofill VALUES ($n, $v, lower($v), $c, $l, $k)";
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("$n", a.Name); cmd.Parameters.AddWithValue("$v", a.Value);
            cmd.Parameters.AddWithValue("$c", a.Created); cmd.Parameters.AddWithValue("$l", a.LastUsed); cmd.Parameters.AddWithValue("$k", a.Count);
            cmd.ExecuteNonQuery();
        }
    }
}
