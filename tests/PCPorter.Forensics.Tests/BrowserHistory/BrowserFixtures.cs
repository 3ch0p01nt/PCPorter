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

    /// <param name="pragmas">Run before the schema, e.g. "PRAGMA page_size=65536; PRAGMA secure_delete=ON;".</param>
    public ChromiumFixture(string profileFolder, string pragmas = "PRAGMA secure_delete=OFF;")
    {
        Directory.CreateDirectory(profileFolder);
        Path = System.IO.Path.Combine(profileFolder, "History");
        _conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path};Pooling=False");
        _conn.Open();
        Exec(pragmas);
        Exec(Schema);
    }

    /// <summary>Runs any statement (deletes, pragmas) on the fixture's open connection.</summary>
    public void Sql(string sql) => Exec(sql);

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

/// <summary>
/// Builds a Firefox profile: places.sqlite and formhistory.sqlite with the real (current Firefox) schemas, and
/// session files compressed with <see cref="Lz4Test"/>.
/// </summary>
internal sealed class FirefoxFixture : IDisposable
{
    public const string PlacesSchema = """
        CREATE TABLE moz_origins ( id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, host TEXT NOT NULL, frecency INTEGER NOT NULL, recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0, UNIQUE (prefix, host) );
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL , description TEXT, preview_image_url TEXT, site_name TEXT, origin_id INTEGER REFERENCES moz_origins(id), recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER);
        CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT, syncStatus INTEGER NOT NULL DEFAULT 0, syncChangeCounter INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
        CREATE TABLE moz_meta (key TEXT PRIMARY KEY, value NOT NULL) WITHOUT ROWID ;
        INSERT INTO moz_bookmarks (id, type, parent, position, title, guid) VALUES
          (1, 2, 0, 0, '', 'root________'), (2, 2, 1, 0, 'menu', 'menu________'), (3, 2, 1, 1, 'toolbar', 'toolbar_____'),
          (4, 2, 1, 2, 'tags', 'tags________'), (5, 2, 1, 3, 'unfiled', 'unfiled_____'), (6, 2, 1, 4, 'mobile', 'mobile______');
        INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'downloads/destinationFileURI'), (2, 'downloads/metaData');
        """;

    public const string FormSchema = """
        CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
        CREATE TABLE moz_deleted_formhistory (id INTEGER PRIMARY KEY, timeDeleted INTEGER, guid TEXT);
        CREATE TABLE moz_sources (id INTEGER PRIMARY KEY, source TEXT NOT NULL);
        CREATE TABLE moz_history_to_sources (history_id INTEGER, source_id INTEGER, PRIMARY KEY (history_id, source_id));
        """;

    readonly Microsoft.Data.Sqlite.SqliteConnection _places;
    public string Folder { get; }

    public FirefoxFixture(string profileFolder, string pragmas = "PRAGMA secure_delete=OFF;")
    {
        Folder = profileFolder;
        Directory.CreateDirectory(profileFolder);
        _places = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(profileFolder, "places.sqlite")};Pooling=False");
        _places.Open();
        Exec(_places, pragmas);
        Exec(_places, PlacesSchema);
    }

    /// <summary>Runs any statement on places.sqlite's open connection.</summary>
    public void Sql(string sql) => Exec(_places, sql);

    public static long PrTime(DateTimeOffset t) => t.ToUnixTimeMilliseconds() * 1000;

    static long Exec(Microsoft.Data.Sqlite.SqliteConnection c, string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
        cmd.CommandText = "SELECT last_insert_rowid()";
        cmd.Parameters.Clear();
        return (long)cmd.ExecuteScalar()!;
    }

    public long Place(string url, string? title = null) =>
        Exec(_places, "INSERT INTO moz_places(url, title, guid) VALUES ($u, $t, 'g')", ("$u", url), ("$t", title));

    public long Visit(long place, DateTimeOffset when, int type, long fromVisit = 0) =>
        Exec(_places, "INSERT INTO moz_historyvisits(from_visit, place_id, visit_date, visit_type, session) VALUES ($f, $p, $d, $t, 0)",
            ("$f", fromVisit), ("$p", place), ("$d", PrTime(when)), ("$t", type));

    public long NewFolder(long parent, string title) =>
        Exec(_places, "INSERT INTO moz_bookmarks(type, parent, title, guid) VALUES (2, $p, $t, 'f')", ("$p", parent), ("$t", title));

    public void Bookmark(long parent, string url, string title, DateTimeOffset added) =>
        Exec(_places, "INSERT INTO moz_bookmarks(type, fk, parent, title, dateAdded, guid) VALUES (1, $fk, $p, $t, $d, 'b')",
            ("$fk", Place(url, title)), ("$p", parent), ("$t", title), ("$d", PrTime(added)));

    public void Download(string url, string fileUri, DateTimeOffset added, string? metaJson)
    {
        var place = Place(url);
        Exec(_places, "INSERT INTO moz_annos(place_id, anno_attribute_id, content, dateAdded) VALUES ($p, 1, $c, $d)", ("$p", place), ("$c", fileUri), ("$d", PrTime(added)));
        if (metaJson is not null)
            Exec(_places, "INSERT INTO moz_annos(place_id, anno_attribute_id, content, dateAdded) VALUES ($p, 2, $c, $d)", ("$p", place), ("$c", metaJson), ("$d", PrTime(added)));
    }

    public void Forms(params (string Field, string Value, int Times, DateTimeOffset First, DateTimeOffset Last)[] rows)
    {
        using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(Folder, "formhistory.sqlite")};Pooling=False");
        c.Open();
        Exec(c, FormSchema);
        foreach (var r in rows)
            Exec(c, "INSERT INTO moz_formhistory(fieldname, value, timesUsed, firstUsed, lastUsed, guid) VALUES ($f, $v, $n, $a, $b, 'g')",
                ("$f", r.Field), ("$v", r.Value), ("$n", r.Times), ("$a", PrTime(r.First)), ("$b", PrTime(r.Last)));
    }

    /// <summary>Writes a session file (relative path, e.g. sessionstore.jsonlz4) as mozLz4.</summary>
    public string Session(string relative, string json)
    {
        var path = Path.Combine(Folder, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, Lz4Test.MozLz4(Encoding.UTF8.GetBytes(json)));
        return path;
    }

    public void Dispose() => _places.Dispose();
}

/// <summary>A minimal LZ4 encoder for tests: literal-only blocks, wrapped as mozLz4 when asked.</summary>
internal static class Lz4Test
{
    public static byte[] LiteralBlock(byte[] data)
    {
        var ms = new MemoryStream();
        int n = data.Length;
        ms.WriteByte((byte)(Math.Min(n, 15) << 4));
        if (n >= 15)
        {
            int rest = n - 15;
            while (rest >= 255) { ms.WriteByte(255); rest -= 255; }
            ms.WriteByte((byte)rest);
        }
        ms.Write(data);
        return ms.ToArray();
    }

    public static byte[] MozLz4(byte[] data) => [.. "mozLz40\0"u8, .. BitConverter.GetBytes((uint)data.Length), .. LiteralBlock(data)];
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
