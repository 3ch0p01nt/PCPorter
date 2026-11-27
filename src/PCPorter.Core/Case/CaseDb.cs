using Microsoft.Data.Sqlite;

namespace PCPorter.Core.Case;

/// <summary>One SQLite file per case. Collectors write normalized rows here; reports and the workbench read from it.</summary>
public sealed class CaseTooNewException(int version) : Exception($"This case was made by a newer PCPorter (case format {version}). Update PCPorter to open it.");

public sealed record ScanInfo(string ScanId, DateTimeOffset StartedUtc, string ToolVersion, string SourceMode, string? MachineId, string? ComputerName, string? OsBuild, string? Volume);
public sealed record ScanItemRow(string Kind, string ItemKey, string Json);
public sealed record ScanDiff(IReadOnlyList<string> Added, IReadOnlyList<string> Removed, IReadOnlyList<string> Changed);

public sealed class CaseDb : IDisposable
{
    public const int CurrentSchema = 2;
    readonly SqliteConnection _conn;
    CaseDb(SqliteConnection conn) => _conn = conn;

    public int SchemaVersion => Convert.ToInt32(Scalar("PRAGMA user_version"));

    public static CaseDb Open(string path)
    {
        // No pooling: closing a case must release the file (and its -wal/-shm) so it can be copied or moved right away.
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        conn.Open();
        var db = new CaseDb(conn);
        try
        {
            db.Exec("PRAGMA journal_mode=WAL;");
            var v = db.SchemaVersion;
            if (v > CurrentSchema) throw new CaseTooNewException(v);
            if (v == 0)
            {
                using (var tx = db._conn.BeginTransaction()) { db.CreateSchema(); tx.Commit(); }   // all or nothing
                v = 1;
            }
            while (v < CurrentSchema) db.MigrateTo(++v);
            return db;
        }
        catch { db.Dispose(); throw; }
    }

    /// <summary>Ordered, transactional upgrades of older case files.</summary>
    void MigrateTo(int version)
    {
        using var tx = _conn.BeginTransaction();
        switch (version)
        {
            case 2:
                Exec("""
                    ALTER TABLE artifacts ADD COLUMN scan_id TEXT;
                    ALTER TABLE artifacts ADD COLUMN item_key TEXT;
                    CREATE TABLE case_meta(key TEXT PRIMARY KEY, value TEXT);
                    CREATE TABLE scans(scan_id TEXT PRIMARY KEY, started_utc INTEGER NOT NULL, finished_utc INTEGER, status TEXT,
                      tool_version TEXT, source_mode TEXT, machine_id TEXT, computer_name TEXT, os_build TEXT, volume TEXT);
                    CREATE TABLE collector_runs(scan_id TEXT NOT NULL, collector TEXT NOT NULL, status TEXT NOT NULL, items INTEGER,
                      ms INTEGER, message TEXT, PRIMARY KEY(scan_id, collector));
                    CREATE TABLE scan_items(scan_id TEXT NOT NULL, kind TEXT NOT NULL, item_key TEXT NOT NULL, json TEXT NOT NULL,
                      PRIMARY KEY(scan_id, kind, item_key));
                    CREATE TABLE tags_v2(item_key TEXT NOT NULL, category TEXT NOT NULL, tag TEXT NOT NULL, note TEXT,
                      PRIMARY KEY(item_key, category, tag));
                    INSERT INTO tags_v2(item_key, category, tag, note) SELECT 'artifact:' || artifact_id, 'artifact', tag, note FROM tags;
                    DROP TABLE tags;
                    ALTER TABLE tags_v2 RENAME TO tags;
                    """);
                break;
            default: throw new InvalidOperationException($"No migration to case format {version}.");
        }
        Exec($"PRAGMA user_version = {version};");
        tx.Commit();
    }

    /// <summary>Runs several writes as one transaction (all saved, or none).</summary>
    public void RunInTransaction(Action work)
    {
        using var tx = _conn.BeginTransaction();
        _inTransaction = true;
        try { work(); tx.Commit(); }
        finally { _inTransaction = false; }
    }
    bool _inTransaction;

    // ---- Scans (schema 2) ----

    public void BeginScan(ScanInfo s)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scans(scan_id, started_utc, status, tool_version, source_mode, machine_id, computer_name, os_build, volume)
            VALUES ($id, $t, 'running', $v, $m, $mid, $cn, $os, $vol)
            """;
        cmd.Parameters.AddWithValue("$id", s.ScanId);
        cmd.Parameters.AddWithValue("$t", s.StartedUtc.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$v", s.ToolVersion);
        cmd.Parameters.AddWithValue("$m", s.SourceMode);
        cmd.Parameters.AddWithValue("$mid", (object?)s.MachineId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cn", (object?)s.ComputerName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$os", (object?)s.OsBuild ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$vol", (object?)s.Volume ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void FinishScan(string scanId, DateTimeOffset finishedUtc, string status) =>
        Run("UPDATE scans SET finished_utc = $t, status = $s WHERE scan_id = $id", ("$t", finishedUtc.ToUnixTimeMilliseconds()), ("$s", status), ("$id", scanId));

    public void RecordCollector(string scanId, string collector, string status, int items, long ms, string? message) =>
        Run("INSERT OR REPLACE INTO collector_runs VALUES ($id, $c, $s, $n, $ms, $msg)",
            ("$id", scanId), ("$c", collector), ("$s", status), ("$n", items), ("$ms", ms), ("$msg", (object?)message ?? DBNull.Value));

    public void SaveItems(string scanId, IEnumerable<ScanItemRow> rows)
    {
        using var tx = _inTransaction ? null : _conn.BeginTransaction();
        using var cmd = _conn.CreateCommand();
        // Duplicate keys within a kind keep the first item (collectors should not produce them; never silently replace).
        cmd.CommandText = "INSERT OR IGNORE INTO scan_items VALUES ($id, $k, $key, $j)";
        var k = cmd.Parameters.Add("$k", SqliteType.Text);
        var key = cmd.Parameters.Add("$key", SqliteType.Text);
        var j = cmd.Parameters.Add("$j", SqliteType.Text);
        cmd.Parameters.AddWithValue("$id", scanId);
        foreach (var r in rows) { k.Value = r.Kind; key.Value = r.ItemKey; j.Value = r.Json; cmd.ExecuteNonQuery(); }
        tx?.Commit();
    }

    public List<ScanItemRow> Items(string scanId, string? kind = null)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT kind, item_key, json FROM scan_items WHERE scan_id = $id AND ($k IS NULL OR kind = $k) ORDER BY kind, item_key";
        cmd.Parameters.AddWithValue("$id", scanId);
        cmd.Parameters.AddWithValue("$k", (object?)kind ?? DBNull.Value);
        using var r = cmd.ExecuteReader();
        var list = new List<ScanItemRow>();
        while (r.Read()) list.Add(new ScanItemRow(r.GetString(0), r.GetString(1), r.GetString(2)));
        return list;
    }

    public List<(string ScanId, DateTimeOffset Started, string? Status, string? Mode)> Scans()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT scan_id, started_utc, status, source_mode FROM scans ORDER BY started_utc";
        using var r = cmd.ExecuteReader();
        var list = new List<(string, DateTimeOffset, string?, string?)>();
        while (r.Read()) list.Add((r.GetString(0), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(1)), r.IsDBNull(2) ? null : r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3)));
        return list;
    }

    /// <summary>Compares two scans of one kind by stable item key.</summary>
    public ScanDiff Diff(string olderScan, string newerScan, string kind)
    {
        var a = Items(olderScan, kind).ToDictionary(x => x.ItemKey, x => x.Json);
        var b = Items(newerScan, kind).ToDictionary(x => x.ItemKey, x => x.Json);
        return new ScanDiff(
            b.Keys.Except(a.Keys).Order().ToList(),
            a.Keys.Except(b.Keys).Order().ToList(),
            b.Keys.Intersect(a.Keys).Where(key => a[key] != b[key]).Order().ToList());
    }

    public void SetTag(string itemKey, string category, string tag, string? note = null) =>
        Run("INSERT OR REPLACE INTO tags VALUES ($k, $c, $t, $n)", ("$k", itemKey), ("$c", category), ("$t", tag), ("$n", (object?)note ?? DBNull.Value));

    public List<(string ItemKey, string Category, string Tag)> Tags()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT item_key, category, tag FROM tags ORDER BY item_key";
        using var r = cmd.ExecuteReader();
        var list = new List<(string, string, string)>();
        while (r.Read()) list.Add((r.GetString(0), r.GetString(1), r.GetString(2)));
        return list;
    }

    void Run(string sql, params (string Name, object Value)[] args)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Schema 1 (the starting point every case file is upgraded from).</summary>
    void CreateSchema() => Exec($"""
        CREATE TABLE artifacts(
          id INTEGER PRIMARY KEY, ts_utc INTEGER, category TEXT NOT NULL, source TEXT NOT NULL,
          artifact TEXT NOT NULL, user TEXT, action TEXT NOT NULL, subject TEXT NOT NULL,
          detail TEXT, confidence INTEGER NOT NULL);
        CREATE INDEX ix_artifacts_ts ON artifacts(ts_utc);
        CREATE INDEX ix_artifacts_cat ON artifacts(category);
        CREATE VIRTUAL TABLE artifacts_fts USING fts5(subject, detail, content='artifacts', content_rowid='id');
        CREATE TRIGGER artifacts_ai AFTER INSERT ON artifacts BEGIN
          INSERT INTO artifacts_fts(rowid, subject, detail) VALUES (new.id, new.subject, new.detail);
        END;
        CREATE TABLE tags(artifact_id INTEGER NOT NULL REFERENCES artifacts(id), tag TEXT NOT NULL, note TEXT,
          PRIMARY KEY(artifact_id, tag));
        PRAGMA user_version = 1;
        """);

    public void Insert(IEnumerable<Artifact> rows)
    {
        using var tx = _inTransaction ? null : _conn.BeginTransaction();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO artifacts(ts_utc, category, source, artifact, user, action, subject, detail, confidence)
            VALUES ($ts, $cat, $src, $art, $user, $act, $sub, $det, $conf)
            """;
        string[] names = ["$ts", "$cat", "$src", "$art", "$user", "$act", "$sub", "$det", "$conf"];
        foreach (var n in names) cmd.Parameters.Add(new SqliteParameter(n, DBNull.Value));
        foreach (var r in rows)
        {
            object?[] values = [r.TsUtc?.ToUnixTimeMilliseconds(), r.Category, r.Source, r.ArtifactName,
                                r.User, r.Action, r.Subject, r.Detail, (int)r.Confidence];
            for (var i = 0; i < values.Length; i++) cmd.Parameters[i].Value = values[i] ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx?.Commit();
    }

    public Dictionary<string, int> CountByCategory()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT category, COUNT(*) FROM artifacts GROUP BY category";
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, int>();
        while (r.Read()) result[r.GetString(0)] = r.GetInt32(1);
        return result;
    }

    /// <summary>Full-text search over subject and detail. User input is treated as a literal phrase.</summary>
    public List<Artifact> Search(string query, int limit = 500)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            SELECT a.ts_utc, a.category, a.source, a.artifact, a.user, a.action, a.subject, a.detail, a.confidence
            FROM artifacts_fts f JOIN artifacts a ON a.id = f.rowid
            WHERE artifacts_fts MATCH $q ORDER BY a.ts_utc LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$q", '"' + query.Replace("\"", "\"\"") + '"');
        cmd.Parameters.AddWithValue("$limit", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<Artifact>();
        while (r.Read())
            list.Add(new Artifact(
                r.IsDBNull(0) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(0)),
                r.GetString(1), r.GetString(2), r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4),
                r.GetString(5), r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7), (Confidence)r.GetInt32(8)));
        return list;
    }

    void Exec(string sql) { using var c = _conn.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }
    object? Scalar(string sql) { using var c = _conn.CreateCommand(); c.CommandText = sql; return c.ExecuteScalar(); }
    public void Dispose() => _conn.Dispose();
}
