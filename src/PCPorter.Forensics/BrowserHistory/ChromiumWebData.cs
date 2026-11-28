using Microsoft.Data.Sqlite;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads saved form entries from a Chromium profile's "Web Data" database. Only the <c>autofill</c> table is read, and
/// the connection is guarded so that no other table (payment cards, IBANs, addresses) can be read through it.
/// </summary>
public static class ChromiumWebData
{
    public const string Table = "autofill";
    public const string AutofillSql = "SELECT name, value, count, date_created, date_last_used FROM autofill";

    public static List<FormEntry> Read(BrowserProfile profile, string workFolder, List<string> notes, CancellationToken ct = default)
    {
        var path = Path.Combine(profile.Folder, "Web Data");
        if (!BrowserProfileFinder.FileExists(path)) return [];
        using var snap = DbSnapshot.Take(path, workFolder, keepRaw: false);      // never carved: its bytes are not held in memory
        using var conn = snap.Open();
        if (UntrustedSqlite.NotPlainTable(conn, Table) is { } why) throw new InvalidDataException($"Web Data: {why}.");
        UntrustedSqlite.AllowOnly(conn, Table);
        var list = new List<FormEntry>();
        int dropped = 0;
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = AutofillSql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if ((list.Count & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
                var field = r.IsDBNull(0) ? null : r.GetValue(0) as string;
                var value = r.IsDBNull(1) ? null : r.GetValue(1) as string;
                var entry = FormFields.Make(profile, field, value, r.IsDBNull(2) ? 0 : r.GetInt64(2),
                    Seconds(r.IsDBNull(3) ? 0 : r.GetInt64(3)), Seconds(r.IsDBNull(4) ? 0 : r.GetInt64(4)));
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

    /// <summary>Chromium's autofill table stores Unix seconds.</summary>
    static DateTimeOffset? Seconds(long s) => s is > 0 and < 1L << 40 ? Timestamps.FromPRTime(s * 1_000_000) : null;
}
