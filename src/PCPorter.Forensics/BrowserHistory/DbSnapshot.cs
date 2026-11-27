using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// A private copy of a browser's SQLite database (with its -wal / -journal files) in the case's work folder. The
/// original is only read through shared handles; the copy is opened read-write so SQLite replays the write-ahead log
/// into the copy, never into the original. Disposing deletes the copy.
/// </summary>
public sealed class DbSnapshot : IDisposable
{
    /// <summary>Raw bytes above this size are not kept in memory (carving skips the file with a warning).</summary>
    public const long RawCap = 512L << 20;

    readonly string _folder;
    readonly List<string> _warnings = [];

    /// <summary>Path of the copied main database file.</summary>
    public string Path { get; }
    public string SourcePath { get; }
    public IReadOnlyList<string> Warnings => _warnings;

    /// <summary>The copied main file's bytes as they were before SQLite opened the copy (null if too large).</summary>
    public byte[]? RawMain { get; }
    /// <summary>The copied write-ahead log's bytes, or null when there was none (or it is too large).</summary>
    public byte[]? RawWal { get; }

    DbSnapshot(string sourcePath, string folder, string path, byte[]? main, byte[]? wal)
    {
        SourcePath = sourcePath;
        _folder = folder;
        Path = path;
        RawMain = main;
        RawWal = wal;
    }

    public static DbSnapshot Take(string dbPath, string workFolder)
    {
        var folder = System.IO.Path.Combine(workFolder, "db-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        try
        {
            var copy = System.IO.Path.Combine(folder, System.IO.Path.GetFileName(dbPath));
            var warnings = new List<string>();
            var main = CopyShared(dbPath, copy, warnings);
            byte[]? wal = null;
            if (File.Exists(dbPath + "-wal")) wal = CopyShared(dbPath + "-wal", copy + "-wal", warnings);
            if (File.Exists(dbPath + "-journal")) CopyShared(dbPath + "-journal", copy + "-journal", null);
            var snap = new DbSnapshot(dbPath, folder, copy, main, wal);
            snap._warnings.AddRange(warnings);
            return snap;
        }
        catch
        {
            TryDelete(folder);
            throw;
        }
    }

    /// <summary>Opens the copy. Pooling is off so the file handle is released on dispose.</summary>
    public SqliteConnection Open()
    {
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = SqliteOpenMode.ReadWrite,     // the private copy may need to replay its write-ahead log
            Pooling = false,
        }.ToString());
        conn.Open();
        return conn;
    }

    /// <summary>Copies a file with a shared read handle; returns its bytes when <paramref name="warnings"/> is set and it is small enough.</summary>
    static byte[]? CopyShared(string from, string to, List<string>? warnings)
    {
        using var src = SourceFiles.OpenRead(from);
        using var dst = new FileStream(to, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
        if (warnings is null || src.Length > RawCap)
        {
            if (warnings is not null)
                warnings.Add($"{System.IO.Path.GetFileName(from)} is larger than {RawCap >> 20} MB, so its free space was not searched for deleted entries.");
            src.CopyTo(dst, 1 << 20);
            return null;
        }
        var bytes = new byte[src.Length];
        src.ReadExactly(bytes);
        dst.Write(bytes);
        return bytes;
    }

    static void TryDelete(string folder)
    {
        try { Directory.Delete(folder, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        TryDelete(_folder);
    }
}
