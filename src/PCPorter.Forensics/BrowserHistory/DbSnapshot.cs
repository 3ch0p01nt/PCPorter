using System.Buffers.Binary;
using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Sources;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// A private copy of a browser's SQLite database (with its -wal / -journal files) in the case's work folder. The
/// original is only read through shared handles; the copy is opened read-write so SQLite replays the write-ahead log
/// into the copy, never into the original. Disposing deletes the copy.
/// <para>
/// A running browser can write while the files are copied one after the other, which leaves a copy whose main file
/// and log do not belong together. So each copy is checked (the log's salts must be the ones it had before the main
/// file was copied, and SQLite's <c>quick_check</c> must pass) and taken again, up to <see cref="Attempts"/> times in
/// all; if no copy passes, the last one is used and <see cref="CopyProblem"/> says why.
/// </para>
/// </summary>
public sealed class DbSnapshot : IDisposable
{
    /// <summary>Raw bytes above this size are not kept in memory (carving skips the file with a warning).</summary>
    public const long RawCap = 512L << 20;

    /// <summary>How many copies are taken at most before an inconsistent one is used anyway.</summary>
    public const int Attempts = 3;

    readonly string _folder;
    readonly List<string> _warnings = [];

    /// <summary>Path of the copied main database file.</summary>
    public string Path { get; }
    public string SourcePath { get; }
    public IReadOnlyList<string> Warnings => _warnings;

    /// <summary>The copied main file's bytes as they were before SQLite opened the copy (null if too large or not kept).</summary>
    public byte[]? RawMain { get; }
    /// <summary>The copied write-ahead log's bytes, or null when there was none (or it is too large, or not kept).</summary>
    public byte[]? RawWal { get; }

    /// <summary>Why even the last copy failed the consistency check, or null when it passed.</summary>
    public string? CopyProblem { get; private set; }

    /// <summary>How many copies were taken (1 when the first one passed).</summary>
    public int CopiesTaken { get; private set; }

    DbSnapshot(string sourcePath, string folder, string path, byte[]? main, byte[]? wal)
    {
        SourcePath = sourcePath;
        _folder = folder;
        Path = path;
        RawMain = main;
        RawWal = wal;
    }

    /// <param name="keepRaw">Keep the raw bytes for carving. False for files that are never carved (form history), so their contents are not held in memory.</param>
    public static DbSnapshot Take(string dbPath, string workFolder, bool keepRaw = true) => Take(dbPath, workFolder, keepRaw, null);

    /// <param name="afterMainCopied">Test hook: runs after the main file of copy number N (1-based) was copied, before its log is.</param>
    internal static DbSnapshot Take(string dbPath, string workFolder, bool keepRaw, Action<int, string>? afterMainCopied)
    {
        for (int attempt = 1; ; attempt++)
        {
            var folder = System.IO.Path.Combine(workFolder, "db-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(folder);
            DbSnapshot? snap = null;
            try
            {
                var copy = System.IO.Path.Combine(folder, System.IO.Path.GetFileName(dbPath));
                var warnings = new List<string>();
                var saltsBefore = SourceSalts(dbPath + "-wal");
                var main = CopyShared(dbPath, copy, keepRaw ? warnings : null);
                afterMainCopied?.Invoke(attempt, copy);
                byte[]? wal = null;
                if (File.Exists(dbPath + "-wal")) wal = CopyShared(dbPath + "-wal", copy + "-wal", keepRaw ? warnings : null);
                if (File.Exists(dbPath + "-journal")) CopyShared(dbPath + "-journal", copy + "-journal", null);
                snap = new DbSnapshot(dbPath, folder, copy, main, wal) { CopiesTaken = attempt };
                snap._warnings.AddRange(warnings);
                var problem = SaltProblem(saltsBefore, CopySalts(copy + "-wal")) ?? QuickCheck(copy);
                if (problem is null || attempt >= Attempts)
                {
                    snap.CopyProblem = problem;
                    return snap;
                }
                snap.Dispose();
            }
            catch
            {
                if (snap is null) TryDelete(folder);
                else snap.Dispose();
                throw;
            }
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

    // ---------------------------------------------------------------- consistency of the copy

    /// <summary>The log header's two salts; they change whenever SQLite starts the log over (after a checkpoint).</summary>
    static (uint, uint)? Salts(ReadOnlySpan<byte> header) =>
        header.Length >= 32 && BinaryPrimitives.ReadUInt32BigEndian(header) is 0x377f0682 or 0x377f0683
            ? (BinaryPrimitives.ReadUInt32BigEndian(header[16..]), BinaryPrimitives.ReadUInt32BigEndian(header[20..]))
            : null;

    static (uint, uint)? SourceSalts(string walPath)
    {
        if (!File.Exists(walPath)) return null;
        try
        {
            using var fs = SourceFiles.OpenRead(walPath);
            Span<byte> header = stackalloc byte[32];
            return fs.ReadAtLeast(header, 32, throwOnEndOfStream: false) == 32 ? Salts(header) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    static (uint, uint)? CopySalts(string walCopy)
    {
        if (!File.Exists(walCopy)) return null;
        using var fs = new FileStream(walCopy, FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> header = stackalloc byte[32];
        return fs.ReadAtLeast(header, 32, throwOnEndOfStream: false) == 32 ? Salts(header) : null;
    }

    /// <summary>
    /// A log that had a header before the main file was copied must still have the same salts in the copy: otherwise
    /// the browser saved the log into the main file and started a new log in between, and the two copies do not match.
    /// </summary>
    static string? SaltProblem((uint, uint)? before, (uint, uint)? copied) =>
        before is { } b && copied != b ? "the browser started a new write-ahead log while the files were being copied" : null;

    /// <summary>SQLite's own quick consistency check on the copy (it replays the copied log first).</summary>
    static string? QuickCheck(string copy)
    {
        try
        {
            using var conn = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = copy, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString());
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA quick_check(1)";
            var result = cmd.ExecuteScalar() as string;
            return string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase) ? null : $"SQLite's consistency check failed ({result ?? "no result"})";
        }
        catch (SqliteException e) { return $"SQLite could not check it ({e.Message.Split('\n')[0].Trim()})"; }
    }

    // ---------------------------------------------------------------- copying

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
