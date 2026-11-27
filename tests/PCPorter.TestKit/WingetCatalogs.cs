using Microsoft.Data.Sqlite;

namespace PCPorter.TestKit;

/// <summary>One package as winget's catalogs store it (values already normalized the way winget writes them).</summary>
public sealed record CatalogPackage(string Id, string Version = "1.0", string[]? ProductCodes = null, string[]? UpgradeCodes = null,
    string[]? NormNames = null, string[]? NormPublishers = null, string[]? Pfns = null, string? ArpMin = null, string? ArpMax = null);

/// <summary>Small winget catalogs with winget's real table layouts: the published index (2.x) and a tracking catalog (1.7).</summary>
public static class WingetCatalogs
{
    public static void CreateV2(string file, params CatalogPackage[] packages)
    {
        Run(file, """
            CREATE TABLE metadata(name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) WITHOUT ROWID;
            INSERT INTO metadata VALUES ('majorVersion','2'),('minorVersion','0');
            CREATE TABLE packages(rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, name TEXT NOT NULL, moniker TEXT, latest_version TEXT NOT NULL, arp_min_version TEXT, arp_max_version TEXT, hash BLOB);
            CREATE TABLE productcodes2(productcode TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(productcode, package)) WITHOUT ROWID;
            CREATE TABLE upgradecodes2(upgradecode TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(upgradecode, package)) WITHOUT ROWID;
            CREATE TABLE norm_names2(norm_name TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_name, package)) WITHOUT ROWID;
            CREATE TABLE norm_publishers2(norm_publisher TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_publisher, package)) WITHOUT ROWID;
            CREATE TABLE pfns2(pfn TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(pfn, package)) WITHOUT ROWID;
            """, (db, tx) =>
        {
            long row = 0;
            foreach (var p in packages)
            {
                row++;
                Exec(db, tx, "INSERT INTO packages(rowid,id,name,latest_version,arp_min_version,arp_max_version) VALUES ($r,$id,$id,$v,$min,$max)",
                    ("$r", row), ("$id", p.Id), ("$v", p.Version), ("$min", (object?)p.ArpMin ?? DBNull.Value), ("$max", (object?)p.ArpMax ?? DBNull.Value));
                foreach (var (table, column, values) in Values(p))
                    foreach (var v in values) Exec(db, tx, $"INSERT OR IGNORE INTO {table}2({column}, package) VALUES ($v, $r)", ("$v", v), ("$r", row));
            }
        });
    }

    /// <summary>A tracking catalog (LocalState\...\installed.db, schema 1.7): values reach a manifest through *_map tables.</summary>
    public static void CreateV1(string file, params CatalogPackage[] packages)
    {
        var ddl = """
            CREATE TABLE metadata(name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) WITHOUT ROWID;
            INSERT INTO metadata VALUES ('majorVersion','1'),('minorVersion','7');
            CREATE TABLE ids(rowid INTEGER PRIMARY KEY, id TEXT NOT NULL);
            CREATE TABLE versions(rowid INTEGER PRIMARY KEY, version TEXT NOT NULL);
            CREATE TABLE manifest(rowid INTEGER PRIMARY KEY, id INT64 NOT NULL, name INT64 NOT NULL, moniker INT64 NOT NULL, version INT64 NOT NULL, channel INT64 NOT NULL, pathpart INT64 NOT NULL, hash BLOB, arp_min_version INT64, arp_max_version INT64);
            """;
        foreach (var (t, c) in new[] { ("productcodes", "productcode"), ("upgradecodes", "upgradecode"), ("norm_names", "norm_name"), ("norm_publishers", "norm_publisher"), ("pfns", "pfn") })
            ddl += $"CREATE TABLE {t}(rowid INTEGER PRIMARY KEY, {c} TEXT NOT NULL); CREATE TABLE {t}_map(manifest INT64 NOT NULL, {c} INT64 NOT NULL, PRIMARY KEY({c}, manifest)) WITHOUT ROWID;\n";
        Run(file, ddl, (db, tx) =>
        {
            long row = 0, value = 0;
            long Version(string? v)
            {
                if (v is null) return 0;
                Exec(db, tx, "INSERT INTO versions(rowid, version) VALUES ($r, $v)", ("$r", ++value), ("$v", v));
                return value;
            }
            foreach (var p in packages)
            {
                row++;
                Exec(db, tx, "INSERT INTO ids(rowid, id) VALUES ($r, $id)", ("$r", row), ("$id", p.Id));
                long min = Version(p.ArpMin), max = Version(p.ArpMax), ver = Version(p.Version);
                Exec(db, tx, "INSERT INTO manifest(rowid,id,name,moniker,version,channel,pathpart,arp_min_version,arp_max_version) VALUES ($r,$r,0,0,$ver,0,0,$min,$max)",
                    ("$r", row), ("$ver", ver), ("$min", min == 0 ? DBNull.Value : (object)min), ("$max", max == 0 ? DBNull.Value : (object)max));
                foreach (var (table, column, values) in Values(p))
                    foreach (var v in values)
                    {
                        Exec(db, tx, $"INSERT INTO {table}(rowid, {column}) VALUES ($k, $v)", ("$k", ++value), ("$v", v));
                        Exec(db, tx, $"INSERT INTO {table}_map(manifest, {column}) VALUES ($r, $k)", ("$r", row), ("$k", value));
                    }
            }
        });
    }

    static IEnumerable<(string Table, string Column, string[] Values)> Values(CatalogPackage p) =>
    [
        ("productcodes", "productcode", p.ProductCodes ?? []), ("upgradecodes", "upgradecode", p.UpgradeCodes ?? []),
        ("norm_names", "norm_name", p.NormNames ?? []), ("norm_publishers", "norm_publisher", p.NormPublishers ?? []), ("pfns", "pfn", p.Pfns ?? []),
    ];

    static void Run(string file, string ddl, Action<SqliteConnection, SqliteTransaction> fill)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        using (var db = new SqliteConnection($"Data Source={file};Pooling=False"))
        {
            db.Open();
            using (var cmd = db.CreateCommand()) { cmd.CommandText = ddl; cmd.ExecuteNonQuery(); }
            using var tx = db.BeginTransaction();
            fill(db, tx);
            tx.Commit();
        }
        SqliteConnection.ClearAllPools();
    }

    static void Exec(SqliteConnection db, SqliteTransaction tx, string sql, params (string Name, object Value)[] args)
    {
        using var cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        cmd.ExecuteNonQuery();
    }
}
