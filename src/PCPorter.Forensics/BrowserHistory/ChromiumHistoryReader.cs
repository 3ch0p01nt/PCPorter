using Microsoft.Data.Sqlite;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads a Chromium-family profile (Chrome, Edge, Brave, Opera, Vivaldi, Chromium): the History database from a private
/// copy, the Bookmarks file, the session files and Web Data's autofill table. Login Data and Cookies are never opened,
/// and Web Data's card, IBAN and address tables are never read.
/// </summary>
public static class ChromiumHistoryReader
{
    const uint CoreMask = 0xFF;
    const uint ChainEnd = 0x20000000, ClientRedirect = 0x40000000, ServerRedirect = 0x80000000;

    const string VisitsSql = """
        SELECT u.url, u.title, v.visit_time, v.transition, v.visit_duration
        FROM visits v JOIN urls u ON u.id = v.url
        ORDER BY v.visit_time, v.id
        """;

    const string KeywordSql = """
        SELECT k.term, u.url, u.last_visit_time
        FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id
        """;

    const string DownloadsSql = "SELECT * FROM downloads ORDER BY start_time, id";
    const string ChainSql = "SELECT url FROM downloads_url_chains WHERE id = $id ORDER BY chain_index LIMIT 1";

    /// <param name="stillOnDisk">Whether a path on the scanned PC still exists (null = cannot tell, e.g. another drive).</param>
    public static ProfileHistory Read(BrowserProfile profile, string workFolder, Func<string, bool?>? stillOnDisk = null, CancellationToken ct = default)
    {
        using var snap = DbSnapshot.Take(Path.Combine(profile.Folder, "History"), workFolder);
        var notes = new List<string>();
        var warnings = new List<string>();
        List<Visit> visits;
        List<Search> searches;
        List<Download> downloads;
        HashSet<string>? liveKeys = null;
        SqliteConnection? conn = null;
        try
        {
            conn = snap.Open();
            var urlSearches = new List<Search>();
            var keys = new List<string>();
            visits = ReadVisits(conn, profile, urlSearches, ct, keys);
            searches = MergeSearches(ReadKeywordSearches(conn, profile, notes), urlSearches);
            downloads = ReadDownloads(conn, profile, stillOnDisk, notes, ct);
            WarnInconsistent(profile, snap, warnings);
            var live = conn;
            visits.AddRange(Carve(profile, snap, notes, warnings, () => SqliteCarver.Chromium(profile, snap.RawMain, snap.RawWal, live, DateTimeOffset.UtcNow, ct)));
            liveKeys = [.. keys];
        }
        catch (SqliteException e) when (IsDamaged(e))
        {
            visits = CarveDamaged(profile, snap, notes, warnings, () => SqliteCarver.Chromium(profile, snap.RawMain, snap.RawWal, null, DateTimeOffset.UtcNow, ct));
            searches = [];
            downloads = [];
        }
        finally { conn?.Dispose(); }
        var bookmarks = Part(profile, "bookmarks", warnings, () => ChromiumBookmarks.Read(profile));
        var tabs = Part(profile, "open and recently closed tabs", warnings, () => ChromiumSessions.Read(profile, notes));
        var forms = Part(profile, "saved form entries", warnings, () => ChromiumWebData.Read(profile, workFolder, notes, ct));
        return new ProfileHistory(visits, searches, downloads, bookmarks, tabs, forms, notes) { Warnings = warnings, VisitKeys = liveKeys };
    }

    /// <summary>
    /// Only the visits of a profile's History database (for older copies, e.g. in restore points), each with its
    /// <see cref="ProfileHistory.VisitKey"/>. Nothing is carved, so the raw bytes are not kept.
    /// </summary>
    internal static List<(Visit Visit, string Key)> ReadVisitsOnly(BrowserProfile profile, string workFolder, CancellationToken ct = default)
    {
        using var snap = DbSnapshot.Take(Path.Combine(profile.Folder, "History"), workFolder, keepRaw: false);
        using var conn = snap.Open();
        var keys = new List<string>();
        return ReadVisits(conn, profile, [], ct, keys).Zip(keys).ToList();
    }

    /// <summary>Reads one optional part of a profile; if it fails, the rest of the profile is still shown.</summary>
    internal static List<T> Part<T>(BrowserProfile profile, string what, List<string> warnings, Func<List<T>> read)
    {
        try { return read(); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            warnings.Add($"{profile.Browser} ({profile.Name}) for {profile.User}: the {what} could not be read: {e.Message.Split('\n')[0].Trim()}");
            return [];
        }
    }

    /// <summary>Recovers deleted visits from the copy's raw bytes; a failure there is a warning, never the end of the profile.</summary>
    internal static IReadOnlyList<Visit> Carve(BrowserProfile profile, DbSnapshot snap, List<string> notes, List<string> warnings, Func<SqliteCarver.Result> carve)
    {
        notes.AddRange(snap.Warnings.Select(w => $"{profile.Browser} ({profile.Name}) for {profile.User}: {w}"));
        try
        {
            var r = carve();
            SqliteCarver.Describe(profile, r, notes);
            return r.Visits;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            warnings.Add($"{profile.Browser} ({profile.Name}) for {profile.User}: deleted history could not be searched: {e.Message.Split('\n')[0].Trim()}");
            return [];
        }
    }

    /// <summary>SQLITE_CORRUPT (11) or SQLITE_NOTADB (26), including their extended codes.</summary>
    internal static bool IsDamaged(SqliteException e) => (e.SqliteErrorCode & 0xFF) is 11 or 26;

    /// <summary>
    /// A copy SQLite cannot open (the file itself is damaged, or the browser kept writing while it was copied): every row
    /// still in its raw bytes is read by the carver (rows the browser still lists too, since nothing can be compared
    /// with), marked "from a damaged copy" (never "deleted"), with a warning.
    /// </summary>
    internal static List<Visit> CarveDamaged(BrowserProfile profile, DbSnapshot snap, List<string> notes, List<string> warnings, Func<SqliteCarver.Result> carve)
    {
        var who = $"{profile.Browser} ({profile.Name}) for {profile.User}";
        var file = Path.GetFileName(snap.SourcePath);
        notes.AddRange(snap.Warnings.Select(w => $"{who}: {w}"));
        var why = $"the copy of the history file {file} could not be opened after {snap.CopiesTaken} tr{(snap.CopiesTaken == 1 ? "y" : "ies")} " +
                  "(the file is damaged, or the browser kept writing to it while it was copied)";
        try
        {
            var r = carve();
            warnings.Add($"{who}: {why}. {r.Visits.Count} visit{(r.Visits.Count == 1 ? " was" : "s were")} read from the copy's raw bytes and " +
                         $"{(r.Visits.Count == 1 ? "is" : "are")} marked \"From a damaged copy\": most are probably still in the browser's history, " +
                         "some may have been deleted. Searches and downloads from this file are not shown.");
            return r.Visits.Select(v => v with { Origin = Origin.DamagedCopy, OriginNote = null }).ToList();
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            warnings.Add($"{who}: {why}, and its raw bytes could not be searched: {e.Message.Split('\n')[0].Trim()}");
            return [];
        }
    }

    /// <summary>A copy that opened although it never passed the consistency check: a warning, since rows may be missing.</summary>
    internal static void WarnInconsistent(BrowserProfile profile, DbSnapshot snap, List<string> warnings)
    {
        if (snap.CopyProblem is null) return;
        warnings.Add($"{profile.Browser} ({profile.Name}) for {profile.User}: no consistent copy of {Path.GetFileName(snap.SourcePath)} could be taken " +
                     $"in {snap.CopiesTaken} tries ({snap.CopyProblem}); the browser was probably writing to it. Some visits may be missing.");
    }

    /// <param name="keys">Filled with each visit's key (same order as the visits), from the address before masking.</param>
    static List<Visit> ReadVisits(SqliteConnection conn, BrowserProfile profile, List<Search> urlSearches, CancellationToken ct, List<string> keys)
    {
        var list = new List<Visit>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = VisitsSql;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            if ((list.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (r.IsDBNull(0) || Timestamps.FromWebKit(r.GetInt64(2)) is not { } when) continue;
            if (MapTransition(unchecked((uint)r.GetInt64(3))) is not { } how) continue;
            var raw = r.GetString(0);
            var title = r.IsDBNull(1) ? null : r.GetString(1);
            var micros = r.IsDBNull(4) ? 0 : r.GetInt64(4);
            list.Add(new Visit(profile, Redactor.Redact(raw), string.IsNullOrEmpty(title) ? null : Redactor.Redact(title),
                when, how, Math.Max(0, micros / 1_000_000)));
            keys.Add(ProfileHistory.VisitKey(raw, when));
            if (SearchTerms.FromUrl(raw) is { } s) urlSearches.Add(new Search(profile, Redactor.Redact(s.Terms), s.Engine, when));
        }
        return list;
    }

    static List<Search> ReadKeywordSearches(SqliteConnection conn, BrowserProfile profile, List<string> notes)
    {
        var list = new List<Search>();
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = KeywordSql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (r.IsDBNull(0) || r.GetString(0).Trim() is not { Length: > 0 } term) continue;
                if (r.IsDBNull(2) || Timestamps.FromWebKit(r.GetInt64(2)) is not { } when) continue;
                var url = r.IsDBNull(1) ? null : r.GetString(1);
                var engine = SearchTerms.FromUrl(url)?.Engine ?? HostOf(url) ?? "Search";
                list.Add(new Search(profile, Redactor.Redact(term), engine, when));
            }
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 1)     // no such table: older or trimmed database
        {
            notes.Add($"{profile.Browser} ({profile.Name}) for {profile.User} has no search-terms table; searches come from the visited addresses only.");
        }
        return list;
    }

    /// <summary>The browser's own search-terms list, plus searches seen in visited addresses that it does not already hold (same terms, same minute).</summary>
    internal static List<Search> MergeSearches(List<Search> keyword, List<Search> fromUrls)
    {
        static string Key(Search s) => s.Terms.ToLowerInvariant() + "|" + s.When.UtcTicks / TimeSpan.TicksPerMinute;
        var seen = keyword.Select(Key).ToHashSet();
        var all = keyword.ToList();
        foreach (var s in fromUrls) if (seen.Add(Key(s))) all.Add(s);
        return all.OrderBy(s => s.When).ThenBy(s => s.Terms, StringComparer.Ordinal).ToList();
    }

    static List<Download> ReadDownloads(SqliteConnection conn, BrowserProfile profile, Func<string, bool?>? stillOnDisk, List<string> notes, CancellationToken ct)
    {
        var list = new List<Download>();
        try
        {
            using var chain = conn.CreateCommand();
            chain.CommandText = ChainSql;
            var id = chain.Parameters.Add("$id", SqliteType.Integer);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = DownloadsSql;
            using var r = cmd.ExecuteReader();
            var cols = Enumerable.Range(0, r.FieldCount).ToDictionary(r.GetName, i => i, StringComparer.OrdinalIgnoreCase);
            string? Text(string name) => cols.TryGetValue(name, out var i) && !r.IsDBNull(i) && r.GetValue(i) is string s && s.Length > 0 ? s : null;
            long Number(string name) => cols.TryGetValue(name, out var i) && !r.IsDBNull(i) && r.GetValue(i) is long n ? n : 0;
            while (r.Read())
            {
                ct.ThrowIfCancellationRequested();
                id.Value = Number("id");
                var first = chain.ExecuteScalar() as string;
                var url = first ?? Text("tab_url") ?? "";
                var target = Text("target_path") ?? Text("current_path") ?? "";
                var referrer = Text("referrer") ?? Text("tab_url");
                var state = Number("state") switch
                {
                    0 => DownloadState.InProgress,
                    1 => DownloadState.Complete,
                    2 => DownloadState.Cancelled,
                    3 or 4 => DownloadState.Interrupted,
                    _ => DownloadState.Unknown,
                };
                list.Add(new Download(profile, Redactor.Redact(url), referrer is null ? null : Redactor.Redact(referrer), target,
                    Timestamps.FromWebKit(Number("start_time")), Number("received_bytes"), state,
                    target.Length == 0 ? null : stillOnDisk?.Invoke(target)));
            }
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 1)
        {
            notes.Add($"{profile.Browser} ({profile.Name}) for {profile.User} has no downloads table.");
        }
        return list;
    }

    static string? HostOf(string? url) => Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Host.Length > 0 ? u.Host : null;

    /// <summary>
    /// Chromium page transition -> how the page was reached; null for sub-frames (parts of a page, not pages).
    /// A redirect that is not the end of its chain is a page the browser passed through, not one that was shown.
    /// </summary>
    public static VisitHow? MapTransition(uint transition)
    {
        var core = transition & CoreMask;
        if (core is 3 or 4) return null;
        if ((transition & (ClientRedirect | ServerRedirect)) != 0 && (transition & ChainEnd) == 0) return VisitHow.Redirect;
        return core switch
        {
            0 => VisitHow.Link,
            1 or 9 or 10 => VisitHow.Typed,
            2 => VisitHow.Bookmark,
            5 => VisitHow.Generated,
            7 => VisitHow.FormSubmit,
            8 => VisitHow.Reload,
            _ => VisitHow.Other,
        };
    }
}
