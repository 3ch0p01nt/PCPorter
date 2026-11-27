using Microsoft.Data.Sqlite;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class DbSnapshotTests
{
    static void Exec(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    static byte[] ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }

    [Fact]
    public void Copy_sees_uncheckpointed_wal_rows_and_the_original_is_untouched()
    {
        var dir = BrowserFixtures.TempDir();
        var work = Path.Combine(dir, "work");
        Directory.CreateDirectory(work);
        var db = Path.Combine(dir, "History");
        try
        {
            using var writer = new SqliteConnection($"Data Source={db};Pooling=False");
            writer.Open();
            Exec(writer, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(v TEXT);");
            Exec(writer, "PRAGMA wal_checkpoint(TRUNCATE);");
            for (int i = 0; i < 25; i++) Exec(writer, $"INSERT INTO t VALUES ('row{i}')");
            Assert.True(new FileInfo(db + "-wal").Length > 0);

            var mainBefore = ReadShared(db);
            var walBefore = ReadShared(db + "-wal");
            var mtimeBefore = File.GetLastWriteTimeUtc(db);

            string folder;
            using (var snap = DbSnapshot.Take(db, work))
            {
                folder = Path.GetDirectoryName(snap.Path)!;
                Assert.StartsWith(work, snap.Path);
                Assert.Equal(mainBefore, snap.RawMain);
                Assert.Equal(walBefore, snap.RawWal);
                using var conn = snap.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT count(*) FROM t";
                Assert.Equal(25L, cmd.ExecuteScalar());
            }

            Assert.False(Directory.Exists(folder));
            Assert.Equal(mainBefore, ReadShared(db));
            Assert.Equal(walBefore, ReadShared(db + "-wal"));
            Assert.Equal(mtimeBefore, File.GetLastWriteTimeUtc(db));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Missing_database_throws_and_leaves_no_folder()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            Assert.ThrowsAny<IOException>(() => DbSnapshot.Take(Path.Combine(dir, "nope"), dir));
            Assert.Empty(Directory.GetDirectories(dir));
        }
        finally { BrowserFixtures.Delete(dir); }
    }
}
