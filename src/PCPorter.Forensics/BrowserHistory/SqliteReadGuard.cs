using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Limits a connection to reading named tables. SQLite asks the authorizer before every column it reads, so a query
/// against any other table (for example Web Data's card tables) fails with "not authorized" instead of returning data.
/// Writes, pragmas, attaches and every other action are refused too.
/// </summary>
public static class SqliteReadGuard
{
    const int Ok = 0, Deny = 1;
    const int ActionRead = 20, ActionSelect = 21, ActionFunction = 31;

    /// <summary>Installs the guard on an open connection; it stays for the connection's lifetime.</summary>
    public static void AllowOnly(SqliteConnection connection, params string[] tables)
    {
        ArgumentNullException.ThrowIfNull(connection.Handle);
        var allowed = new HashSet<string>(tables, StringComparer.OrdinalIgnoreCase);
        strdelegate_authorizer check = (_, action, table, _, _, _) => action switch
        {
            ActionSelect or ActionFunction => Ok,
            ActionRead when table is not null && allowed.Contains(table) => Ok,
            _ => Deny,
        };
        if (raw.sqlite3_set_authorizer(connection.Handle, check, null) != raw.SQLITE_OK)
            throw new InvalidOperationException("The database read guard could not be installed.");
    }
}
