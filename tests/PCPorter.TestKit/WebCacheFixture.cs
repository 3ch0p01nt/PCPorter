using System.Text;
using Microsoft.Isam.Esent.Interop;

namespace PCPorter.TestKit;

/// <summary>
/// Builds a synthetic Internet Explorer / legacy Edge WebCacheV01.dat (ESE, logs with base name V01) holding the subset
/// of the real schema PCPorter reads: a Containers table (ContainerId, Name, Directory) and one Container_&lt;id&gt; table
/// per container (EntryId, Url, AccessedTime, AccessCount, ResponseHeaders). The engine is shut down cleanly.
/// </summary>
public static class WebCacheFixture
{
    public const string FileName = "WebCacheV01.dat";

    public sealed record Entry(string Url, DateTimeOffset Accessed, int AccessCount = 1, byte[]? ResponseHeaders = null);

    public sealed record Container(long Id, string Name, IReadOnlyList<Entry> Entries);

    /// <summary>Creates the database and its log files in <paramref name="folder"/>; returns the database path.</summary>
    public static string Create(string folder, params Container[] containers)
    {
        Directory.CreateDirectory(folder);
        var dir = folder.TrimEnd('\\') + "\\";
        var db = Path.Combine(folder, FileName);
        using var instance = new Instance($"pcporter-webcache-test-{Guid.NewGuid():N}");
        instance.Parameters.SystemDirectory = dir;
        instance.Parameters.LogFileDirectory = dir;
        instance.Parameters.TempDirectory = dir;
        instance.Parameters.BaseName = "V01";
        instance.Parameters.LogFileSize = 1024;
        instance.Parameters.NoInformationEvent = true;
        instance.Init();
        using var session = new Session(instance);
        Api.JetCreateDatabase(session, db, null, out var dbid, CreateDatabaseGrbit.None);

        var text = new JET_COLUMNDEF { coltyp = JET_coltyp.LongText, cp = JET_CP.Unicode };
        var int64 = new JET_COLUMNDEF { coltyp = JET_coltyp.Currency };
        using (var tx = new Transaction(session))
        {
            Api.JetCreateTable(session, dbid, "Containers", 0, 100, out var table);
            Api.JetAddColumn(session, table, "ContainerId", int64, null, 0, out var idCol);
            Api.JetAddColumn(session, table, "Name", text, null, 0, out var nameCol);
            Api.JetAddColumn(session, table, "Directory", text, null, 0, out var dirCol);
            foreach (var c in containers)
                using (var update = new Update(session, table, JET_prep.Insert))
                {
                    Api.SetColumn(session, table, idCol, c.Id);
                    Api.SetColumn(session, table, nameCol, c.Name, Encoding.Unicode);
                    Api.SetColumn(session, table, dirCol, $@"C:\Users\bob\AppData\Local\Microsoft\Windows\INetCache\{c.Name}\", Encoding.Unicode);
                    update.Save();
                }
            Api.JetCloseTable(session, table);
            tx.Commit(CommitTransactionGrbit.None);
        }

        foreach (var c in containers)
        {
            using var tx = new Transaction(session);
            Api.JetCreateTable(session, dbid, $"Container_{c.Id}", 0, 100, out var table);
            Api.JetAddColumn(session, table, "EntryId", int64, null, 0, out var entryCol);
            Api.JetAddColumn(session, table, "AccessCount", new JET_COLUMNDEF { coltyp = JET_coltyp.Long }, null, 0, out var countCol);
            Api.JetAddColumn(session, table, "AccessedTime", int64, null, 0, out var timeCol);
            Api.JetAddColumn(session, table, "Url", text, null, 0, out var urlCol);
            Api.JetAddColumn(session, table, "ResponseHeaders", new JET_COLUMNDEF { coltyp = JET_coltyp.LongBinary }, null, 0, out var headersCol);
            long entry = 1;
            foreach (var e in c.Entries)
                using (var update = new Update(session, table, JET_prep.Insert))
                {
                    Api.SetColumn(session, table, entryCol, entry++);
                    Api.SetColumn(session, table, countCol, e.AccessCount);
                    Api.SetColumn(session, table, timeCol, e.Accessed.UtcDateTime.ToFileTimeUtc());
                    Api.SetColumn(session, table, urlCol, e.Url, Encoding.Unicode);
                    if (e.ResponseHeaders is { } h) Api.SetColumn(session, table, headersCol, h);
                    update.Save();
                }
            Api.JetCloseTable(session, table);
            tx.Commit(CommitTransactionGrbit.None);
        }
        Api.JetCloseDatabase(session, dbid, CloseDatabaseGrbit.None);
        Api.JetDetachDatabase(session, db);
        return db;
    }

    /// <summary>Download response headers as IE writes them: binary fields, then UTF-16 strings (address, referrer, saved path).</summary>
    public static byte[] DownloadHeaders(string url, string referrer, string savedPath)
    {
        var bytes = new List<byte> { 0x01, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x13, 0x00 };
        foreach (var s in new[] { url, referrer, savedPath })
            bytes.AddRange(Encoding.Unicode.GetBytes(s + "\0"));
        return [.. bytes];
    }
}
