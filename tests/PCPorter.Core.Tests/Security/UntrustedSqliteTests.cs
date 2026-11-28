using Microsoft.Data.Sqlite;
using PCPorter.Core.Security;

namespace PCPorter.Core.Tests.Security;

public sealed class UntrustedSqliteTests : IDisposable
{
    readonly SqliteConnection _conn = new("Data Source=:memory:");

    public UntrustedSqliteTests()
    {
        _conn.Open();
        Exec("""
            CREATE TABLE t(x, y); INSERT INTO t VALUES (1, 'a'), (2, NULL);
            CREATE TABLE secret(card); INSERT INTO secret VALUES ('4111');
            CREATE VIEW v AS SELECT x FROM t;
            CREATE VIEW leak AS SELECT card AS x FROM secret;
            CREATE VIRTUAL TABLE f USING fts4(body);
            """);
    }

    public void Dispose() => _conn.Dispose();

    void Exec(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    object? Scalar(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }

    int ErrorOf(string sql) => Assert.Throws<SqliteException>(() =>
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        using var r = cmd.ExecuteReader();
        while (r.Read()) { }
    }).SqliteErrorCode;

    [Fact]
    public void Hardening_turns_on_the_safety_pragmas()
    {
        UntrustedSqlite.Harden(_conn);
        Assert.Equal(0L, Scalar("PRAGMA trusted_schema"));
        Assert.Equal(1L, Scalar("PRAGMA cell_size_check"));
        Assert.Equal(1L, Scalar("PRAGMA query_only"));
    }

    [Fact]
    public void Hardening_limits_value_size_and_refuses_writes_and_views()
    {
        UntrustedSqlite.Harden(_conn);
        Assert.Equal(1000L, Scalar("SELECT length(zeroblob(1000))"));
        Assert.Equal(18, ErrorOf("SELECT zeroblob(1000000000)"));              // SQLITE_TOOBIG
        Assert.Equal(18, ErrorOf($"SELECT zeroblob({UntrustedSqlite.MaxValueBytes + 1})"));
        Assert.NotEqual(0, ErrorOf("DELETE FROM t"));
        Assert.NotEqual(0, ErrorOf("SELECT * FROM v"));                         // views are off
        Assert.NotEqual(0, ErrorOf("ATTACH ':memory:' AS other"));
    }

    [Fact]
    public void A_runaway_query_is_stopped_by_the_step_budget()
    {
        UntrustedSqlite.Harden(_conn, stepBudget: 5_000_000);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Equal(9, ErrorOf("WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c) SELECT count(*) FROM c"));   // SQLITE_INTERRUPT
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20));
    }

    [Fact]
    public void Plain_tables_and_missing_ones_pass_views_and_virtual_tables_do_not()
    {
        Assert.Null(UntrustedSqlite.NotPlainTable(_conn, "t", "T", "missing"));
        Assert.Contains("\"v\" table is a view", UntrustedSqlite.NotPlainTable(_conn, "t", "v"));
        Assert.Contains("\"f\" table is a virtual table", UntrustedSqlite.NotPlainTable(_conn, "f"));
    }

    [Fact]
    public void The_read_guard_allows_plain_reads_of_named_tables_only()
    {
        UntrustedSqlite.Harden(_conn);
        UntrustedSqlite.AllowOnly(_conn, "t", "v", "leak");
        Assert.Equal(2L, Scalar("SELECT count(*) FROM t WHERE ifnull(y, 'b') IN ('a', 'b')"));
        using (var cmd = _conn.CreateCommand())
        {
            cmd.CommandText = "PRAGMA table_info(t)";
            using var r = cmd.ExecuteReader();
            Assert.True(r.Read());
        }
        foreach (var sql in new[]
        {
            "SELECT card FROM secret", "SELECT x FROM leak", "SELECT zeroblob(10) FROM t", "SELECT randomblob(10)",
            "SELECT load_extension('x')", "PRAGMA table_info(secret)", "PRAGMA cell_size_check=OFF", "SELECT sql FROM sqlite_master",
            "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c LIMIT 5) SELECT count(*) FROM c",
        })
            Assert.NotEqual(0, ErrorOf(sql));
    }
}
