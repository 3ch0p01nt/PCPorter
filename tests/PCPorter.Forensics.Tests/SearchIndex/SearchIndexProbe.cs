using System.Security.Principal;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.SearchIndex;

public sealed class AdminFactAttribute : FactAttribute
{
    public AdminFactAttribute()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "Requires an elevated (administrator) test run.";
    }
}

/// <summary>Discovery probe: prints the Windows 11 search index schema (table names, property metadata). Read-only.</summary>
public class SearchIndexProbe(ITestOutputHelper output)
{
    const string Db = @"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db";

    /// <summary>Checks value encodings: id byte order (vs this user's thumbcache ids) and path text encoding.</summary>
    [AdminFact]
    [Trait("Category", "Admin")]
    public void Print_value_encodings()
    {
        var localIds = new HashSet<ulong>();
        var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer");
        foreach (var f in Directory.EnumerateFiles(explorer, "thumbcache_*.db"))
        {
            if (f.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) continue;
            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var bytes = new byte[fs.Length]; fs.ReadExactly(bytes);
            if (bytes.Length == 0) continue;
            foreach (var e in PCPorter.Forensics.Thumbcache.ThumbcacheParser.Parse(bytes, f).Entries) localIds.Add(e.CacheId);
        }
        output.WriteLine($"local thumbcache ids: {localIds.Count}");

        var uri = "file:" + Db.Replace('\\', '/') + "?immutable=1";
        using var conn = new SqliteConnection($"Data Source={uri};Mode=ReadOnly");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT t.WorkId, t.Value, p.Value FROM SystemIndex_1_PropertyStore t
            LEFT JOIN SystemIndex_1_PropertyStore p ON p.WorkId = t.WorkId AND p.ColumnId = 33
            WHERE t.ColumnId = 352
            """;
        using var r = cmd.ExecuteReader();
        int rows = 0, le = 0, be = 0, printed = 0;
        while (r.Read())
        {
            rows++;
            if (rows == 1) output.WriteLine($"value types: id={r.GetValue(1).GetType().Name} path={(r.IsDBNull(2) ? "null" : r.GetValue(2).GetType().Name)}");
            var id = r.GetValue(1) switch { byte[] b => b, long l => BitConverter.GetBytes(l), var o => System.Text.Encoding.UTF8.GetBytes(o.ToString()!) };
            if (id.Length == 8)
            {
                if (localIds.Contains(BitConverter.ToUInt64(id))) le++;
                if (localIds.Contains(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(id))) be++;
            }
            if (printed < 5 && !r.IsDBNull(2))
            {
                var pathText = r.GetValue(2) is byte[] pb ? System.Text.Encoding.Unicode.GetString(pb) : r.GetValue(2).ToString()!;
                bool match = id.Length == 8 && localIds.Contains(BitConverter.ToUInt64(id));
                output.WriteLine($"work={r.GetInt64(0)} idHex={Convert.ToHexString(id)} matchesLocalLE={match} pathPrefix={pathText[..Math.Min(3, pathText.Length)]}... len={pathText.Length}");
                printed++;
            }
        }
        output.WriteLine($"index rows with a thumbnail id: {rows}; matches little-endian={le} big-endian={be}");
    }

    [AdminFact]
    [Trait("Category", "Admin")]
    public void Print_schema()
    {
        output.WriteLine($"exists={File.Exists(Db)} size={new FileInfo(Db).Length}");
        foreach (var f in Directory.EnumerateFiles(Path.GetDirectoryName(Db)!))
            output.WriteLine($"file {Path.GetFileName(f)} {new FileInfo(f).Length}");

        var uri = "file:" + Db.Replace('\\', '/') + "?immutable=1";
        using var conn = new SqliteConnection($"Data Source={uri};Mode=ReadOnly");
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name";
            using var r = cmd.ExecuteReader();
            while (r.Read()) output.WriteLine($"{r.GetString(0)} {r.GetString(1)} :: {(r.IsDBNull(2) ? "" : r.GetString(2))}");
        }
        foreach (var t in new[] { "SystemIndex_1_PropertyStore_Metadata", "SystemIndex_PropertyStore_Metadata" })
        {
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"SELECT * FROM {t} WHERE UniqueKey LIKE '%Thumbnail%' OR UniqueKey LIKE '%ItemPathDisplay%' OR UniqueKey LIKE '%ItemUrl%'";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                    output.WriteLine(t + ": " + string.Join(" | ", Enumerable.Range(0, r.FieldCount).Select(i => $"{r.GetName(i)}={r.GetValue(i)}")));
            }
            catch (Exception ex) { output.WriteLine($"{t}: {ex.Message}"); }
        }
    }
}
