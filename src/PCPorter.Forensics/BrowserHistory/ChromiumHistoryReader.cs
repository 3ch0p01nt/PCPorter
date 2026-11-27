using Microsoft.Data.Sqlite;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads a Chromium-family profile's History database (Chrome, Edge, Brave, Opera, Vivaldi, Chromium) from a private
/// copy. Only the history tables are queried; Login Data, Cookies and Web Data's card tables are never opened.
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

    public static ProfileHistory Read(BrowserProfile profile, string workFolder, CancellationToken ct = default)
    {
        using var snap = DbSnapshot.Take(Path.Combine(profile.Folder, "History"), workFolder);
        using var conn = snap.Open();
        var visits = ReadVisits(conn, profile, ct);
        return ProfileHistory.Empty with { Visits = visits };
    }

    public static IReadOnlyList<Visit> ReadVisits(SqliteConnection conn, BrowserProfile profile, CancellationToken ct)
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
            var title = r.IsDBNull(1) ? null : r.GetString(1);
            var micros = r.IsDBNull(4) ? 0 : r.GetInt64(4);
            list.Add(new Visit(profile, Redactor.Redact(r.GetString(0)), string.IsNullOrEmpty(title) ? null : Redactor.Redact(title),
                when, how, Math.Max(0, micros / 1_000_000)));
        }
        return list;
    }

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
            3 or 4 => null,
            5 => VisitHow.Generated,
            7 => VisitHow.FormSubmit,
            8 => VisitHow.Reload,
            _ => VisitHow.Other,
        };
    }
}
