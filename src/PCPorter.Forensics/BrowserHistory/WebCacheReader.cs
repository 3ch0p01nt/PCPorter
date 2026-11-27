using System.ComponentModel;
using System.Text;
using Microsoft.Isam.Esent;
using Microsoft.Isam.Esent.Interop;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;
using PCPorter.Core.Time;
using PCPorter.Forensics.Ese;
using PCPorter.Forensics.SearchIndex;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads Internet Explorer / legacy Edge history from WebCacheV01.dat (ESE). The database and its logs are copied
/// (through <see cref="SourceFiles"/>, shared read) into a private work folder, log replay runs on the copy only, and the
/// copy is attached read-only and deleted afterwards. Containers named <c>History</c> or <c>MSHist*</c> give visits
/// (Url, AccessedTime, AccessCount); the <c>iedownload</c> container gives downloads. Cookies and cached content are
/// never read. A damaged or unsupported file is a warning, never an exception.
/// </summary>
public static class WebCacheReader
{
    public const string DatabaseFileName = "WebCacheV01.dat";
    const string LogBaseName = "V01";
    const string DisplayName = "PCPorter web history reader";
    static readonly string[] CopyPatterns = [DatabaseFileName, LogBaseName + "*.log", LogBaseName + ".chk", "*.jrs"];

    /// <param name="readFrom">Where the WebCache files are read (e.g. inside a shadow copy); default: the profile's folder.</param>
    public static ProfileHistory Read(BrowserProfile profile, string workFolder, Func<string, bool?>? stillOnDisk = null,
        CancellationToken ct = default, string? readFrom = null)
    {
        var who = $"{profile.Browser} for {profile.User}";
        var visits = new List<Visit>();
        var searches = new List<Search>();
        var downloads = new List<Download>();
        var notes = new List<string>();
        var warnings = new List<string>();
        var copy = Path.Combine(workFolder, "webcache-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var skipped = Copy(readFrom ?? profile.Folder, copy, ct);
            var db = Path.Combine(copy, DatabaseFileName);
            Api.JetGetDatabaseFileInfo(db, out JET_DBINFOMISC info, JET_DbInfo.Misc);
            EseCopy.SetPageSize(info.cbPageSize);
            if (info.dbstate != JET_dbstate.CleanShutdown)
            {
                var error = EseCopy.RecoverWithEngine(copy, LogBaseName, DisplayName);
                if (!EseCopy.IsClean(db)) error = EseCopy.RunEsentutl(copy, LogBaseName) ?? error;
                if (!EseCopy.IsClean(db))
                {
                    var missing = skipped.Count > 0 ? $" Some log files could not be copied ({string.Join(", ", skipped)})." : "";
                    warnings.Add($"{who}: the history file could not be read: its copy could not be repaired ({error ?? "unknown error"}).{missing}");
                    return Result();
                }
            }
            ReadDatabase(copy, db, profile, visits, searches, downloads, stillOnDisk, ct);
        }
        catch (Exception e) when (e is EsentException or IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            warnings.Add($"{who}: the history file could not be read ({e.Message.Split('\n')[0].Trim()}).");
            visits.Clear(); searches.Clear(); downloads.Clear();
        }
        finally
        {
            EseCopy.TryDeleteFolder(copy);
        }
        return Result();

        ProfileHistory Result() => new(
            visits.OrderBy(v => v.When).ThenBy(v => v.Url, StringComparer.Ordinal).ToList(),
            ChromiumHistoryReader.MergeSearches([], searches), downloads.OrderBy(d => d.Started).ToList(), [], [], [], notes) { Warnings = warnings };
    }

    /// <summary>Copies the database and its logs with shared reads. Returns the log files that could not be copied.</summary>
    static List<string> Copy(string folder, string copy, CancellationToken ct)
    {
        Directory.CreateDirectory(copy);
        var skipped = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pattern in CopyPatterns)
            foreach (var source in SourceFiles.Files(folder, pattern))
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(source);
                if (!seen.Add(name)) continue;
                try
                {
                    using var input = SourceFiles.OpenRead(source);
                    using var output = new FileStream(Path.Combine(copy, name), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
                    input.CopyTo(output, 1 << 20);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    if (name.Equals(DatabaseFileName, StringComparison.OrdinalIgnoreCase)) throw;
                    skipped.Add(name);
                }
            }
        if (!seen.Contains(DatabaseFileName)) throw new IOException($"{DatabaseFileName} was not found or is outside the drive being read.");
        return skipped;
    }

    enum Kind { History, Downloads }

    static void ReadDatabase(string copy, string db, BrowserProfile profile, List<Visit> visits, List<Search> searches,
        List<Download> downloads, Func<string, bool?>? stillOnDisk, CancellationToken ct)
    {
        using var instance = EseCopy.CreateInstance(copy, LogBaseName, recovery: false, DisplayName);
        instance.Init();
        using var session = new Session(instance);
        Api.JetAttachDatabase(session, db, AttachDatabaseGrbit.ReadOnly);
        try
        {
            Api.JetOpenDatabase(session, db, null, out var dbid, OpenDatabaseGrbit.ReadOnly);
            try
            {
                var tables = Api.GetTableNames(session, dbid).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (!tables.Contains("Containers")) throw new InvalidOperationException("it has no Containers table");
                var seen = new HashSet<(string, long)>();
                foreach (var (id, name) in Containers(session, dbid))
                {
                    Kind? kind = name.Equals("History", StringComparison.OrdinalIgnoreCase) || name.StartsWith("MSHist", StringComparison.OrdinalIgnoreCase)
                        ? Kind.History
                        : name.Equals("iedownload", StringComparison.OrdinalIgnoreCase) ? Kind.Downloads : null;
                    var table = $"Container_{id}";
                    if (kind is null || !tables.Contains(table)) continue;
                    foreach (var e in Entries(session, dbid, table, ct))
                    {
                        if (kind == Kind.History) AddVisit(profile, e, seen, visits, searches);
                        else if (Download(profile, e, stillOnDisk) is { } d) downloads.Add(d);
                    }
                }
            }
            finally { Api.JetCloseDatabase(session, dbid, CloseDatabaseGrbit.None); }
        }
        finally { Api.JetDetachDatabase(session, db); }
    }

    static void AddVisit(BrowserProfile profile, Entry e, HashSet<(string, long)> seen, List<Visit> visits, List<Search> searches)
    {
        if (CleanUrl(e.Url) is not { } url || e.When is not { } when) return;
        if (!seen.Add((url, when.ToUnixTimeSeconds()))) return;            // History and the MSHist day/week containers repeat visits
        var note = e.Count > 1 ? $"opened {e.Count} times; the last time is shown" : null;
        visits.Add(new Visit(profile, Redactor.Redact(url), null, when, VisitHow.Other, 0, Origin.Live, note));
        if (SearchTerms.FromUrl(url) is { } s) searches.Add(new Search(profile, Redactor.Redact(s.Terms), s.Engine, when));
    }

    /// <summary>A download: the address from the entry (or its headers), the referrer and saved path from the headers (best effort).</summary>
    static Download? Download(BrowserProfile profile, Entry e, Func<string, bool?>? stillOnDisk)
    {
        var strings = e.Headers is { Length: > 0 } h ? Utf16Strings(h) : [];
        var addresses = strings.Select(CleanUrl).OfType<string>().Where(u => !u.StartsWith("file:", StringComparison.OrdinalIgnoreCase)).Distinct().ToList();
        var url = CleanUrl(e.Url) ?? addresses.FirstOrDefault();
        if (url is null) return null;
        var referrer = addresses.FirstOrDefault(a => a != url);
        var target = strings.LastOrDefault(IsWindowsPath) ?? "";
        return new Download(profile, Redactor.Redact(url), referrer is null ? null : Redactor.Redact(referrer), target, e.When, 0,
            DownloadState.Unknown, target.Length == 0 ? null : stillOnDisk?.Invoke(target));
    }

    static bool IsWindowsPath(string s) =>
        (s.Length > 3 && char.IsAsciiLetter(s[0]) && s[1] == ':' && s[2] == '\\') || (s.Length > 2 && s.StartsWith(@"\\", StringComparison.Ordinal));

    /// <summary>Runs of printable UTF-16 characters (at least 4 long) at both byte alignments.</summary>
    static List<string> Utf16Strings(byte[] b)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        for (int start = 0; start <= 1; start++)
        {
            for (int i = start; i + 1 < b.Length; i += 2)
            {
                var c = (char)(b[i] | (b[i + 1] << 8));
                if (c >= 0x20 && c != 0x7F && c < 0xD800) sb.Append(c);
                else Flush();
            }
            Flush();
        }
        return list;

        void Flush()
        {
            if (sb.Length >= 4) list.Add(sb.ToString());
            sb.Clear();
        }
    }

    /// <summary>
    /// The address without the cache's prefix ("Visited: user@" in History, ":&lt;dates&gt;: user@" in MSHist,
    /// "iedownload:"), or null when it is not a web page or local file (res://, about:, javascript:, cookies...).
    /// </summary>
    public static string? CleanUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        if (s.StartsWith("Visited:", StringComparison.OrdinalIgnoreCase) || s.StartsWith(':'))
        {
            int colon = s.IndexOf(": ", 1, StringComparison.Ordinal);
            if (colon < 0) return null;
            s = s[(colon + 2)..].TrimStart();
            int at = s.IndexOf('@');                                        // Windows account names cannot contain '@'
            if (at >= 0 && at < s.IndexOf(':')) s = s[(at + 1)..];
        }
        else if (s.StartsWith("iedownload:", StringComparison.OrdinalIgnoreCase)) s = s["iedownload:".Length..];
        return s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
               || s.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
            ? s : null;
    }

    readonly record struct Entry(string? Url, DateTimeOffset? When, long Count, byte[]? Headers);

    static List<(long Id, string Name)> Containers(Session session, JET_DBID dbid)
    {
        var list = new List<(long, string)>();
        var columns = Api.GetTableColumns(session, dbid, "Containers").ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        if (!columns.TryGetValue("ContainerId", out var idCol) || !columns.TryGetValue("Name", out var nameCol))
            throw new InvalidOperationException("its Containers table has no ContainerId or Name column");
        Api.JetOpenTable(session, dbid, "Containers", null, 0, OpenTableGrbit.ReadOnly | OpenTableGrbit.Sequential, out var table);
        try
        {
            if (!Api.TryMoveFirst(session, table)) return list;
            do
            {
                if (Number(Api.RetrieveColumn(session, table, idCol.Columnid)) is { } id && Text(session, table, nameCol) is { } name)
                    list.Add((id, name.Trim()));
            }
            while (Api.TryMoveNext(session, table));
        }
        finally { Api.JetCloseTable(session, table); }
        return list;
    }

    static List<Entry> Entries(Session session, JET_DBID dbid, string tableName, CancellationToken ct)
    {
        var list = new List<Entry>();
        var columns = Api.GetTableColumns(session, dbid, tableName).ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        if (!columns.TryGetValue("Url", out var urlCol)) return list;
        var timeCol = columns.GetValueOrDefault("AccessedTime");
        var countCol = columns.GetValueOrDefault("AccessCount");
        var headersCol = columns.GetValueOrDefault("ResponseHeaders");
        Api.JetOpenTable(session, dbid, tableName, null, 0, OpenTableGrbit.ReadOnly | OpenTableGrbit.Sequential, out var table);
        try
        {
            if (!Api.TryMoveFirst(session, table)) return list;
            do
            {
                if ((list.Count & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
                var ticks = timeCol is null ? null : Number(Api.RetrieveColumn(session, table, timeCol.Columnid));
                var count = countCol is null ? null : Number(Api.RetrieveColumn(session, table, countCol.Columnid));
                list.Add(new Entry(Text(session, table, urlCol), ticks is long t && t > 0 ? Timestamps.FromFileTime(t) : null, count ?? 0,
                    headersCol is null ? null : Api.RetrieveColumn(session, table, headersCol.Columnid)));
            }
            while (Api.TryMoveNext(session, table));
        }
        finally { Api.JetCloseTable(session, table); }
        return list;
    }

    static string? Text(Session session, JET_TABLEID table, ColumnInfo column) =>
        Api.RetrieveColumn(session, table, column.Columnid) is { Length: > 0 } bytes ? EseSearchIndexPathResolver.DecodeText(bytes, column.Cp == JET_CP.ASCII) : null;

    /// <summary>A little-endian integer column of any width (Long, Currency, LongLong...).</summary>
    static long? Number(byte[]? b) => b?.Length switch
    {
        1 => b[0],
        2 => BitConverter.ToInt16(b),
        4 => BitConverter.ToInt32(b),
        8 => BitConverter.ToInt64(b),
        _ => null,
    };
}
