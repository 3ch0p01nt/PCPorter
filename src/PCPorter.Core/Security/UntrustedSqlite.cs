using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace PCPorter.Core.Security;

/// <summary>
/// Opening SQLite files that come from a possibly infected PC (browser history, form history, winget catalogs, the
/// search index) inside an elevated process. The file's schema is the attacker's: a "table" can be a view that joins
/// itself six times, a virtual table, or a column default calling zeroblob(1e9). So every such connection is
/// <see cref="Harden"/>ed right after it opens, every table is checked with <see cref="NotPlainTable"/> before it is
/// read, and <see cref="AllowOnly"/> limits the connection to reading the tables the reader names.
/// </summary>
public static class UntrustedSqlite
{
    /// <summary>The largest text or blob SQLite will make or return on these connections.</summary>
    public const int MaxValueBytes = 8 << 20;
    /// <summary>The longest SQL statement (the schema's own CREATE statements count).</summary>
    public const int MaxSqlBytes = 1 << 20;
    /// <summary>SQLite virtual-machine steps per connection before its queries are stopped (far above any real file).</summary>
    public const long DefaultStepBudget = 2_000_000_000;
    const int StepsPerCheck = 10_000;

    /// <summary>Functions a read query may call; everything else (zeroblob, randomblob, load_extension, ...) is refused.</summary>
    static readonly HashSet<string> Functions = new(StringComparer.OrdinalIgnoreCase)
    {
        "ifnull", "coalesce", "nullif", "iif", "length", "lower", "upper", "trim", "ltrim", "rtrim", "substr", "substring",
        "instr", "abs", "typeof", "count", "min", "max", "sum", "total", "avg", "like", "glob",
    };

    /// <summary>
    /// A step budget for a file: real queries here scan each table a few times, so their work grows with the file's
    /// size, while a hostile join grows far faster. At least <see cref="DefaultStepBudget"/>, else 64 steps per byte.
    /// </summary>
    public static long BudgetFor(string path)
    {
        long size;
        try { size = new FileInfo(path).Length; } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { size = 0; }
        return Math.Max(DefaultStepBudget, size * 64);
    }

    /// <summary>Opens a connection (pooling off, so the handle and file close on dispose) and hardens it.</summary>
    public static SqliteConnection Open(SqliteConnectionStringBuilder builder, long stepBudget = DefaultStepBudget)
    {
        builder.Pooling = false;
        var conn = new SqliteConnection(builder.ToString());
        try
        {
            conn.Open();
            Harden(conn, stepBudget);
            return conn;
        }
        catch
        {
            conn.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Defensive mode (no writable schema, no shadow-table writes), an untrusted schema (functions in views, triggers,
    /// defaults and CHECKs must be harmless), no views, triggers or extensions, size limits, page cell checks, read-only
    /// queries and a step budget. Call it right after Open, before any other statement.
    /// </summary>
    public static void Harden(SqliteConnection conn, long stepBudget = DefaultStepBudget)
    {
        var db = conn.Handle ?? throw new InvalidOperationException("The connection is not open.");
        foreach (var (op, on) in new[]
        {
            (raw.SQLITE_DBCONFIG_DEFENSIVE, 1), (raw.SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0), (raw.SQLITE_DBCONFIG_ENABLE_VIEW, 0),
            (raw.SQLITE_DBCONFIG_ENABLE_TRIGGER, 0), (raw.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0), (raw.SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, 0),
            (raw.SQLITE_DBCONFIG_WRITABLE_SCHEMA, 0),
        })
            if (raw.sqlite3_db_config(db, op, on, out var now) != raw.SQLITE_OK || now != on)
                throw new InvalidOperationException($"SQLite safety setting {op} could not be applied.");
        raw.sqlite3_limit(db, raw.SQLITE_LIMIT_LENGTH, MaxValueBytes);
        raw.sqlite3_limit(db, raw.SQLITE_LIMIT_SQL_LENGTH, MaxSqlBytes);
        raw.sqlite3_limit(db, raw.SQLITE_LIMIT_ATTACHED, 0);
        long left = stepBudget / StepsPerCheck;
        raw.sqlite3_progress_handler(db, StepsPerCheck, _ => --left < 0 ? 1 : 0, null);   // nonzero stops the query (SQLITE_INTERRUPT)
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA trusted_schema=OFF; PRAGMA cell_size_check=ON; PRAGMA query_only=ON;";
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Null when each named table is a plain table or does not exist (the reader's own "no such table" handling then
    /// applies); otherwise why the first one that is a view or a virtual table is not read. Run it before
    /// <see cref="AllowOnly"/>, which refuses the schema table.
    /// </summary>
    public static string? NotPlainTable(SqliteConnection conn, params string[] tables)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT type, sql FROM sqlite_master WHERE name = $n COLLATE NOCASE";
        var name = cmd.Parameters.Add("$n", SqliteType.Text);
        foreach (var t in tables)
        {
            name.Value = t;
            using var r = cmd.ExecuteReader();
            if (!r.Read()) continue;
            var type = r.IsDBNull(0) ? "" : r.GetString(0);
            var sql = r.IsDBNull(1) ? "" : r.GetString(1);
            if (type == "table" && !sql.TrimStart().StartsWith("CREATE VIRTUAL", StringComparison.OrdinalIgnoreCase)) continue;
            var what = type == "table" ? "a virtual table" : type == "view" ? "a view" : $"a {type}";
            return $"its \"{t}\" table is {what}, not a plain table (the program that made the file never creates one; it may have been tampered with)";
        }
        return null;
    }

    /// <summary>
    /// Limits the connection to reading the named tables. SQLite asks before every column it reads, so a query against
    /// any other table fails with "not authorized". Reads through a view or trigger, functions outside a short list,
    /// recursive queries, writes, attaches and pragmas (except table_info of an allowed table) are refused too.
    /// It stays for the connection's lifetime.
    /// </summary>
    public static void AllowOnly(SqliteConnection connection, params string[] tables)
    {
        var db = connection.Handle ?? throw new InvalidOperationException("The connection is not open.");
        var allowed = new HashSet<string>(tables, StringComparer.OrdinalIgnoreCase);
        strdelegate_authorizer check = (_, action, p0, p1, _, insideViewOrTrigger) =>
            insideViewOrTrigger is not null ? raw.SQLITE_DENY
            : action switch
            {
                raw.SQLITE_SELECT => raw.SQLITE_OK,
                raw.SQLITE_READ when p0 is not null && allowed.Contains(p0) => raw.SQLITE_OK,
                // Microsoft.Data.Sqlite's GetBytes/GetStream looks up the table's key through pragma_table_info; the
                // PRAGMA check below still decides which table's columns it may list.
                raw.SQLITE_READ when string.Equals(p0, "pragma_table_info", StringComparison.OrdinalIgnoreCase) => raw.SQLITE_OK,
                raw.SQLITE_FUNCTION when p1 is not null && Functions.Contains(p1) => raw.SQLITE_OK,
                raw.SQLITE_PRAGMA when string.Equals(p0, "table_info", StringComparison.OrdinalIgnoreCase) && p1 is not null && allowed.Contains(p1) => raw.SQLITE_OK,
                _ => raw.SQLITE_DENY,
            };
        if (raw.sqlite3_set_authorizer(db, check, null) != raw.SQLITE_OK)
            throw new InvalidOperationException("The database read guard could not be installed.");
    }
}
