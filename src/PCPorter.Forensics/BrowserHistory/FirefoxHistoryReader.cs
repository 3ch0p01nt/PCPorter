using System.Text.Json;
using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads a Firefox profile: places.sqlite (visits, bookmarks, download annotations) and formhistory.sqlite from private
/// copies, and the open / recently closed tabs from the session files (mozLz4-compressed JSON). Saved passwords
/// (logins.json, key4.db), certificates (cert9.db) and cookies are never opened.
/// </summary>
public static class FirefoxHistoryReader
{
    const string VisitsSql = """
        SELECT p.url, p.title, v.visit_date, v.visit_type,
               EXISTS (SELECT 1 FROM moz_historyvisits r WHERE r.from_visit = v.id AND r.visit_type IN (5, 6)) AS redirected
        FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
        ORDER BY v.visit_date, v.id
        """;

    const string BookmarksSql = """
        SELECT b.id, b.type, b.parent, b.title, b.dateAdded, b.guid, p.url
        FROM moz_bookmarks b LEFT JOIN moz_places p ON p.id = b.fk
        ORDER BY b.dateAdded, b.id
        """;

    const string DownloadsSql = """
        SELECT a.place_id, p.url, n.name, a.content, a.dateAdded
        FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id
        WHERE n.name IN ('downloads/destinationFileURI', 'downloads/metaData')
        ORDER BY a.place_id, a.id
        """;

    static readonly string[] VisitTables = ["moz_historyvisits", "moz_places"];
    /// <summary>Every table the places.sqlite connection may read (the read guard refuses all others).</summary>
    static readonly string[] Tables = ["moz_historyvisits", "moz_places", "moz_bookmarks", "moz_annos", "moz_anno_attributes"];

    public const string FormTable = "moz_formhistory";
    public const string FormSql = "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory";

    /// <summary>Session files, newest first by time written; the first that decodes is used.</summary>
    static readonly string[] SessionFiles = [@"sessionstore-backups\recovery.jsonlz4", "sessionstore.jsonlz4", @"sessionstore-backups\previous.jsonlz4"];

    static readonly Dictionary<string, string> RootFolders = new(StringComparer.Ordinal)
    {
        ["menu________"] = "Bookmarks menu",
        ["toolbar_____"] = "Bookmarks toolbar",
        ["unfiled_____"] = "Other bookmarks",
        ["mobile______"] = "Mobile bookmarks",
    };
    const string TagsRoot = "tags________", Root = "root________";

    const long SessionFileCap = 64L << 20;

    public static ProfileHistory Read(BrowserProfile profile, string workFolder, Func<string, bool?>? stillOnDisk = null, CancellationToken ct = default)
    {
        var notes = new List<string>();
        var warnings = new List<string>();
        List<Visit> visits;
        List<Search> searches;
        List<Bookmark> bookmarks;
        List<Download> downloads;
        HashSet<string>? liveKeys = null;
        using (var snap = DbSnapshot.Take(Path.Combine(profile.Folder, "places.sqlite"), workFolder))
        {
            SqliteConnection? conn = null;
            try
            {
                conn = snap.Open();
                var live = conn;
                var refused = ChromiumHistoryReader.RefusedParts(conn, profile, snap, warnings, ("visits", VisitTables),
                    ("bookmarks", ["moz_bookmarks", "moz_places"]), ("downloads", ["moz_annos", "moz_anno_attributes", "moz_places"]));
                UntrustedSqlite.AllowOnly(conn, Tables);
                var urlSearches = new List<Search>();
                var keys = new List<string>();
                visits = refused.Contains("visits") ? [] : ReadVisits(conn, profile, urlSearches, ct, keys);
                searches = ChromiumHistoryReader.MergeSearches([], urlSearches);
                bookmarks = refused.Contains("bookmarks") ? [] : ChromiumHistoryReader.Part(profile, "bookmarks", warnings, () => ReadBookmarks(live, profile));
                downloads = refused.Contains("downloads") ? [] : ChromiumHistoryReader.Part(profile, "downloads", warnings, () => ReadDownloads(live, profile, stillOnDisk, notes, ct));
                ChromiumHistoryReader.WarnInconsistent(profile, snap, warnings);
                visits.AddRange(ChromiumHistoryReader.Carve(profile, snap, notes, warnings,
                    () => SqliteCarver.Firefox(profile, snap.RawMain, snap.RawWal, live, DateTimeOffset.UtcNow, ct)));
                liveKeys = [.. keys];
            }
            catch (SqliteException e) when (ChromiumHistoryReader.IsDamaged(e))
            {
                visits = ChromiumHistoryReader.CarveDamaged(profile, snap, notes, warnings,
                    () => SqliteCarver.Firefox(profile, snap.RawMain, snap.RawWal, null, DateTimeOffset.UtcNow, ct));
                searches = [];
                bookmarks = [];
                downloads = [];
            }
            finally { conn?.Dispose(); }
        }
        var forms = ChromiumHistoryReader.Part(profile, "saved form entries", warnings, () => ReadForms(profile, workFolder, notes, ct));
        var tabs = ChromiumHistoryReader.Part(profile, "open and recently closed tabs", warnings, () => ReadSession(profile, notes));
        return new ProfileHistory(visits, searches, downloads, bookmarks, tabs, forms, notes) { Warnings = warnings, VisitKeys = liveKeys };
    }

    /// <summary>Only the visits of a profile's places.sqlite (for older copies, e.g. in restore points), each with its key; nothing is carved.</summary>
    internal static List<(Visit Visit, string Key)> ReadVisitsOnly(BrowserProfile profile, string workFolder, CancellationToken ct = default)
    {
        using var snap = DbSnapshot.Take(Path.Combine(profile.Folder, "places.sqlite"), workFolder, keepRaw: false);
        using var conn = snap.Open();
        if (UntrustedSqlite.NotPlainTable(conn, VisitTables) is { } why) throw new InvalidDataException($"places.sqlite: {why}.");
        UntrustedSqlite.AllowOnly(conn, VisitTables);
        var keys = new List<string>();
        return ReadVisits(conn, profile, [], ct, keys).Zip(keys).ToList();
    }

    static List<Visit> ReadVisits(SqliteConnection conn, BrowserProfile profile, List<Search> urlSearches, CancellationToken ct, List<string> keys)
    {
        var list = new List<Visit>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = VisitsSql;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            if ((list.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (r.IsDBNull(0) || r.IsDBNull(2) || Timestamps.FromPRTime(r.GetInt64(2)) is not { } when) continue;
            if (MapVisitType(r.IsDBNull(3) ? 0 : r.GetInt32(3), !r.IsDBNull(4) && r.GetInt64(4) != 0) is not { } how) continue;
            var raw = r.GetString(0);
            var title = r.IsDBNull(1) ? null : r.GetString(1);
            list.Add(new Visit(profile, Redactor.Redact(raw), string.IsNullOrEmpty(title) ? null : Redactor.Redact(title), when, how, 0));
            keys.Add(ProfileHistory.VisitKey(raw, when));
            if (SearchTerms.FromUrl(raw) is { } s) urlSearches.Add(new Search(profile, Redactor.Redact(s.Terms), s.Engine, when));
        }
        return list;
    }

    /// <summary>
    /// Firefox visit type -> how the page was reached; null for embedded parts of pages (4) and framed links (8).
    /// Firefox stores 5/6 on the page a redirect led TO, so that page counts as a link and the page that redirected
    /// (the visit the 5/6 visit came from) is the one marked Redirect, as for Chromium.
    /// </summary>
    public static VisitHow? MapVisitType(int visitType, bool redirectedAway)
    {
        if (visitType is 4 or 8) return null;
        if (redirectedAway) return VisitHow.Redirect;
        return visitType switch
        {
            1 or 5 or 6 => VisitHow.Link,
            2 => VisitHow.Typed,
            3 => VisitHow.Bookmark,
            9 => VisitHow.Reload,
            _ => VisitHow.Other,                               // 7 download, unknown types
        };
    }

    static List<Bookmark> ReadBookmarks(SqliteConnection conn, BrowserProfile profile)
    {
        var rows = new Dictionary<long, (long Type, long Parent, string? Title, long Added, string? Guid, string? Url)>();
        var order = new List<long>();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = BookmarksSql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var id = r.GetInt64(0);
                rows[id] = (r.IsDBNull(1) ? 0 : r.GetInt64(1), r.IsDBNull(2) ? 0 : r.GetInt64(2), r.IsDBNull(3) ? null : r.GetString(3),
                    r.IsDBNull(4) ? 0 : r.GetInt64(4), r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6));
                order.Add(id);
            }
        }

        // Folder path of an item: the titles of its parents up to a root folder. Items under "tags" are tags, not bookmarks.
        string? FolderOf(long parent)
        {
            var parts = new List<string>();
            for (int depth = 0; depth < 100 && rows.TryGetValue(parent, out var p); depth++, parent = p.Parent)
            {
                if (p.Guid == TagsRoot) return null;
                if (p.Guid == Root) break;
                if (p.Guid is not null && RootFolders.TryGetValue(p.Guid, out var label)) { parts.Add(label); break; }
                parts.Add(Redactor.Redact(p.Title ?? ""));
            }
            parts.Reverse();
            return string.Join("/", parts);
        }

        var list = new List<Bookmark>();
        foreach (var id in order)
        {
            var b = rows[id];
            if (b.Type != 1 || string.IsNullOrEmpty(b.Url) || b.Url.StartsWith("place:", StringComparison.OrdinalIgnoreCase)) continue;
            if (FolderOf(b.Parent) is not { } folder) continue;
            list.Add(new Bookmark(profile, Redactor.Redact(b.Title ?? ""), Redactor.Redact(b.Url), folder, Timestamps.FromPRTime(b.Added)));
        }
        return list;
    }

    static List<Download> ReadDownloads(SqliteConnection conn, BrowserProfile profile, Func<string, bool?>? stillOnDisk, List<string> notes, CancellationToken ct)
    {
        var byPlace = new Dictionary<long, (string Url, string? Target, DateTimeOffset? Added, string? Meta)>();
        var order = new List<long>();
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = DownloadsSql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                ct.ThrowIfCancellationRequested();
                var place = r.GetInt64(0);
                if (!byPlace.TryGetValue(place, out var d)) { d = (r.IsDBNull(1) ? "" : r.GetString(1), null, null, null); order.Add(place); }
                var content = r.IsDBNull(3) ? null : r.GetValue(3) as string;
                if (r.GetString(2) == "downloads/destinationFileURI")
                    d = d with { Target = PathFromFileUri(content), Added = r.IsDBNull(4) ? null : Timestamps.FromPRTime(r.GetInt64(4)) };
                else
                    d = d with { Meta = content };
                byPlace[place] = d;
            }
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 1)
        {
            notes.Add($"{profile.Browser} ({profile.Name}) for {profile.User} has no download records.");
            return [];
        }

        var list = new List<Download>();
        foreach (var place in order)
        {
            var d = byPlace[place];
            if (d.Target is null) continue;
            var (state, bytes, end) = Metadata(d.Meta);
            // The saved-as path (decoded from its file: address) is masked; on-disk is checked with the real one.
            list.Add(new Download(profile, Redactor.Redact(d.Url), null, Redactor.Redact(d.Target), d.Added ?? end, bytes, state, stillOnDisk?.Invoke(d.Target)));
        }
        return list.OrderBy(d => d.Started).ToList();
    }

    /// <summary>downloads/metaData JSON: state (1 finished, 2 failed, 3 cancelled, 4 paused), endTime (ms), fileSize.</summary>
    static (DownloadState State, long Bytes, DateTimeOffset? End) Metadata(string? json)
    {
        if (string.IsNullOrEmpty(json)) return (DownloadState.Unknown, 0, null);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return (DownloadState.Unknown, 0, null);
            long Number(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : 0;
            var state = Number("state") switch
            {
                1 => DownloadState.Complete,
                2 => DownloadState.Interrupted,
                3 => DownloadState.Cancelled,
                0 or 4 => DownloadState.InProgress,
                _ => DownloadState.Unknown,
            };
            var end = Number("endTime");
            return (state, Math.Max(0, Number("fileSize")), end > 0 && end < 1L << 50 ? Timestamps.FromPRTime(end * 1000) : null);
        }
        catch (JsonException) { return (DownloadState.Unknown, 0, null); }
    }

    /// <summary>file:///C:/Users/bob/Downloads/a%20b.zip -> C:\Users\bob\Downloads\a b.zip.</summary>
    static string? PathFromFileUri(string? uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && u.IsFile && u.LocalPath.Length > 0 ? u.LocalPath : null;

    static List<FormEntry> ReadForms(BrowserProfile profile, string workFolder, List<string> notes, CancellationToken ct)
    {
        var path = Path.Combine(profile.Folder, "formhistory.sqlite");
        if (!BrowserProfileFinder.FileExists(path)) return [];
        using var snap = DbSnapshot.Take(path, workFolder, keepRaw: false);      // never carved: its bytes are not held in memory
        using var conn = snap.Open();
        if (UntrustedSqlite.NotPlainTable(conn, FormTable) is { } why) throw new InvalidDataException($"formhistory.sqlite: {why}.");
        UntrustedSqlite.AllowOnly(conn, FormTable);
        var list = new List<FormEntry>();
        int dropped = 0;
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = FormSql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if ((list.Count & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
                var field = r.IsDBNull(0) ? null : r.GetValue(0) as string;
                var value = r.IsDBNull(1) ? null : r.GetValue(1) as string;
                var entry = FormFields.Make(profile, field, value, r.IsDBNull(2) ? 0 : r.GetInt64(2),
                    r.IsDBNull(3) ? null : Timestamps.FromPRTime(r.GetInt64(3)), r.IsDBNull(4) ? null : Timestamps.FromPRTime(r.GetInt64(4)));
                if (entry is null) { if (!string.IsNullOrWhiteSpace(field)) dropped++; }
                else list.Add(entry);
            }
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 1)
        {
            notes.Add($"{profile.Browser} ({profile.Name}) for {profile.User} has no saved form entries table.");
        }
        if (dropped > 0) notes.Add(FormFields.DroppedNote(profile, dropped));
        return list.OrderByDescending(f => f.Last).ThenBy(f => f.Field, StringComparer.Ordinal).ThenBy(f => f.Value, StringComparer.Ordinal).ToList();
    }

    static List<OpenTab> ReadSession(BrowserProfile profile, List<string> notes)
    {
        var files = SessionFiles.Select(f => Path.Combine(profile.Folder, f)).Where(BrowserProfileFinder.FileExists)
            .OrderByDescending(File.GetLastWriteTimeUtc).ToList();
        foreach (var file in files)
        {
            byte[] json;
            try { json = Lz4Block.DecodeMozLz4(SourceFiles.ReadAllBytes(file, SessionFileCap)); }
            catch (InvalidDataException e)
            {
                notes.Add($"The session file {Path.GetFileName(file)} of {profile.Browser} ({profile.Name}) for {profile.User} could not be unpacked ({e.Message}); its tabs were not read.");
                continue;
            }
            try { return ParseSession(profile, json); }
            catch (JsonException)
            {
                notes.Add($"The session file {Path.GetFileName(file)} of {profile.Browser} ({profile.Name}) for {profile.User} is damaged; its tabs were not read.");
            }
        }
        return [];
    }

    /// <summary>
    /// Session JSON: <c>windows[].tabs[].entries[]</c> (the entry at the 1-based <c>index</c> is showing),
    /// <c>windows[]._closedTabs[].state</c> and <c>_closedWindows[].tabs[]</c> (recently closed).
    /// </summary>
    public static List<OpenTab> ParseSession(BrowserProfile profile, ReadOnlyMemory<byte> json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256 });
        var list = new List<OpenTab>();
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return list;
        int window = 0;
        foreach (var w in Array(root, "windows"))
        {
            window++;
            foreach (var tab in Array(w, "tabs"))
                Add(list, profile, tab, window, TabState.Open, Millis(tab, "lastAccessed"));
            foreach (var closed in Array(w, "_closedTabs"))
                if (closed.TryGetProperty("state", out var state) && state.ValueKind == JsonValueKind.Object)
                    Add(list, profile, state, window, TabState.RecentlyClosed, Millis(closed, "closedAt") ?? Millis(state, "lastAccessed"));
        }
        foreach (var w in Array(root, "_closedWindows"))
        {
            window++;
            var closedAt = Millis(w, "closedAt");
            foreach (var tab in Array(w, "tabs"))
                Add(list, profile, tab, window, TabState.RecentlyClosed, Millis(tab, "lastAccessed") ?? closedAt);
        }
        return list;
    }

    static void Add(List<OpenTab> list, BrowserProfile profile, JsonElement tab, int window, TabState state, DateTimeOffset? when)
    {
        var entries = Array(tab, "entries").ToList();
        if (entries.Count == 0) return;
        int index = tab.TryGetProperty("index", out var i) && i.ValueKind == JsonValueKind.Number && i.TryGetInt32(out var n) ? n : entries.Count;
        var entry = entries[Math.Clamp(index, 1, entries.Count) - 1];
        if (Text(entry, "url") is not { Length: > 0 } url) return;
        var title = Text(entry, "title");
        list.Add(new OpenTab(profile, Redactor.Redact(url), string.IsNullOrEmpty(title) ? null : Redactor.Redact(title), window, state, when));
    }

    static IEnumerable<JsonElement> Array(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object) : [];

    static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Session times are milliseconds since 1970.</summary>
    static DateTimeOffset? Millis(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var ms) && ms is > 0 and < 1L << 50
            ? Timestamps.FromPRTime(ms * 1000) : null;
}
