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

    /// <summary>
    /// A rollback journal is never copied. Opening a copy next to a hot journal makes SQLite roll it back, and a
    /// crafted journal from an infected old drive can name a "super-journal" that SQLite then DELETES: any file,
    /// with administrator rights. The journal only holds an unfinished transaction, so nothing is lost.
    /// </summary>
    [Fact]
    public void A_rollback_journal_is_never_copied_next_to_the_copy()
    {
        var dir = BrowserFixtures.TempDir();
        var work = Path.Combine(dir, "work");
        Directory.CreateDirectory(work);
        var db = Path.Combine(dir, "History");
        try
        {
            using (var c = new SqliteConnection($"Data Source={db};Pooling=False"))
            {
                c.Open();
                Exec(c, "PRAGMA journal_mode=DELETE; CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('a');");
            }
            var victim = Path.Combine(dir, "victim.txt");
            File.WriteAllText(victim, "keep me");
            // Stand-in for a crafted hot journal; its bytes don't matter, only that it is not carried over.
            File.WriteAllText(db + "-journal", "journal naming " + victim);

            // SQLite would quietly delete an invalid journal when the copy is opened, so check the source journal is
            // never even read: then a crafted one can never reach SQLite.
            var reads = new List<string>();
            using (PCPorter.Collectors.Sources.SourceFiles.Observe((kind, path) => { if (kind == "read") reads.Add(Path.GetFileName(path)); }))
            using (var snap = DbSnapshot.Take(db, work))
            {
                Assert.DoesNotContain("History-journal", reads);
                Assert.Contains("History", reads);
                Assert.False(File.Exists(snap.Path + "-journal"));
                using var conn = snap.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT count(*) FROM t";
                Assert.Equal(1L, cmd.ExecuteScalar());
            }
            Assert.True(File.Exists(victim));
            Assert.True(File.Exists(db + "-journal"));   // the source is never touched either
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
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

    static long Count(DbSnapshot snap)
    {
        using var conn = snap.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT count(*) FROM t";
        return (long)cmd.ExecuteScalar()!;
    }

    [Fact]
    public void A_log_restarted_between_copying_the_main_file_and_the_log_is_copied_again()
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

            // The browser saves its log into the main file and starts a new one while PCPorter copies: a torn copy.
            using var snap = DbSnapshot.Take(db, work, keepRaw: true, (attempt, _) =>
            {
                if (attempt != 1) return;
                Exec(writer, "PRAGMA wal_checkpoint(TRUNCATE);");
                for (int i = 25; i < 30; i++) Exec(writer, $"INSERT INTO t VALUES ('row{i}')");
            });

            Assert.Equal(2, snap.CopiesTaken);
            Assert.Null(snap.CopyProblem);
            Assert.Equal(30L, Count(snap));
            Assert.Single(Directory.GetDirectories(work));                   // the torn copy was deleted
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    static void Tear(string copy)
    {
        using var fs = new FileStream(copy, FileMode.Open, FileAccess.ReadWrite);
        fs.Position = 4096;                                                    // page 2: the table's b-tree page
        fs.Write(Enumerable.Repeat((byte)0xA5, 4096).ToArray());
    }

    static string MakeDb(string dir)
    {
        var db = Path.Combine(dir, "History");
        using var c = new SqliteConnection($"Data Source={db};Pooling=False");
        c.Open();
        Exec(c, "PRAGMA page_size=4096; CREATE TABLE t(v TEXT);");
        for (int i = 0; i < 40; i++) Exec(c, $"INSERT INTO t VALUES ('row{i}')");
        return db;
    }

    [Fact]
    public void A_copy_that_fails_the_consistency_check_is_taken_again()
    {
        var dir = BrowserFixtures.TempDir();
        var work = Path.Combine(dir, "work");
        Directory.CreateDirectory(work);
        try
        {
            var db = MakeDb(dir);
            using var snap = DbSnapshot.Take(db, work, keepRaw: true, (attempt, copy) => { if (attempt == 1) Tear(copy); });

            Assert.Equal(2, snap.CopiesTaken);
            Assert.Null(snap.CopyProblem);
            Assert.Equal(40L, Count(snap));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void After_three_damaged_copies_the_last_one_is_used_and_says_why()
    {
        var dir = BrowserFixtures.TempDir();
        var work = Path.Combine(dir, "work");
        Directory.CreateDirectory(work);
        try
        {
            var db = MakeDb(dir);
            int taken = 0;
            using var snap = DbSnapshot.Take(db, work, keepRaw: true, (attempt, copy) => { taken = attempt; Tear(copy); });

            Assert.Equal(DbSnapshot.Attempts, taken);
            Assert.Equal(DbSnapshot.Attempts, snap.CopiesTaken);
            Assert.NotNull(snap.CopyProblem);
            Assert.Single(Directory.GetDirectories(work));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Raw_bytes_are_not_kept_when_not_asked_for()
    {
        var dir = BrowserFixtures.TempDir();
        var work = Path.Combine(dir, "work");
        Directory.CreateDirectory(work);
        try
        {
            using var snap = DbSnapshot.Take(MakeDb(dir), work, keepRaw: false);
            Assert.Null(snap.RawMain);
            Assert.Null(snap.RawWal);
            Assert.Empty(snap.Warnings);
            Assert.Equal(40L, Count(snap));
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
