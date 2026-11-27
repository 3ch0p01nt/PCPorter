using Microsoft.Data.Sqlite;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.SearchIndex;

/// <summary>
/// Maps thumbnail cache ids to original paths using the Windows 11 search index (Windows.db, SQLite).
/// Opened read-only with <c>immutable=1</c>: no locks are taken, so the Search service is never blocked
/// and nothing is written. Changes still in the index's write-ahead log are not seen.
/// Verified layout (Win11 26200): SystemIndex_1_PropertyStore(WorkId, ColumnId, Value) where ColumnId is
/// SystemIndex_1_PropertyStore_Metadata.Id; System.ThumbnailCacheId = 8-byte little-endian blob,
/// System.ItemPathDisplay = text.
/// </summary>
/// <param name="copyToFolder">
/// When set, Windows.db and its -wal/-shm files are copied there first and the copy is opened normally, so the most
/// recent index changes (still in the write-ahead log) are included. Slower and needs free space; the copy is deleted.
/// </param>
public sealed class SearchIndexPathResolver(string databasePath, IProgress<string>? progress = null, string? copyToFolder = null) : IThumbnailPathResolver
{
    public const string DefaultWindows11Path = @"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db";
    const string Windows10Path = @"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb";

    readonly List<string> _notes = [];
    public IReadOnlyList<string> Notes => _notes;

    /// <summary>Picks the right resolver for this PC, or one that only explains why paths are unavailable.</summary>
    public static IThumbnailPathResolver ForThisPc(IProgress<string>? progress = null)
    {
        if (File.Exists(DefaultWindows11Path)) return new SearchIndexPathResolver(DefaultWindows11Path, progress);
        if (File.Exists(Windows10Path))
            return new NoteResolver("This PC uses the Windows 10 search index format; use SearchIndexResolverFactory.ForPc to read it.");
        return new NoteResolver("No Windows Search index was found (or it is not readable without administrator rights). Original file paths are shown as unknown.");
    }

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds)
    {
        var result = new Dictionary<ulong, string>();
        if (cacheIds.Count == 0) return result;
        var wanted = cacheIds as ISet<ulong> ?? cacheIds.ToHashSet();

        string? copyDir = null;
        try
        {
            var source = databasePath;
            if (copyToFolder is not null)
            {
                progress?.Report("Copying the search index so its most recent changes are included");
                copyDir = Path.Combine(copyToFolder, "index-" + Guid.NewGuid().ToString("N")[..8]);
                Directory.CreateDirectory(copyDir);
                source = Path.Combine(copyDir, Path.GetFileName(databasePath));
                foreach (var suffix in new[] { "", "-wal", "-shm" })
                    if (File.Exists(databasePath + suffix)) CopyShared(databasePath + suffix, source + suffix);
            }

            using var conn = Open(source, immutable: copyDir is null);
            var idColumn = ColumnId(conn, "System.ThumbnailCacheId");
            var pathColumn = ColumnId(conn, "System.ItemPathDisplay");
            var folderColumn = ColumnId(conn, "System.ItemFolderPathDisplay");
            var nameColumn = ColumnId(conn, "System.ItemNameDisplay");
            var urlColumn = ColumnId(conn, "System.ItemUrl");
            if (idColumn is null || (pathColumn is null && urlColumn is null && (folderColumn is null || nameColumn is null)))
            {
                _notes.Add("The search index does not record thumbnail ids on this PC. Original file paths are shown as unknown.");
                return result;
            }

            // Pass 1: one scan of the thumbnail-id column, keeping only the ids we need.
            progress?.Report("Reading the search index (this can take a few minutes on large indexes)");
            var workIds = new Dictionary<long, ulong>();
            var buf = new byte[8];
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT WorkId, Value FROM SystemIndex_1_PropertyStore WHERE ColumnId = $c";
                cmd.Parameters.AddWithValue("$c", idColumn);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    if (r.IsDBNull(1) || r.GetBytes(1, 0, null, 0, 0) != 8) continue;
                    r.GetBytes(1, 0, buf, 0, 8);
                    var id = BitConverter.ToUInt64(buf);
                    if (wanted.Contains(id)) workIds[r.GetInt64(0)] = id;
                }
            }

            // Pass 2: primary-key lookups of the path for each matching item, with fallbacks.
            using var lookup = conn.CreateCommand();
            lookup.CommandText = "SELECT Value FROM SystemIndex_1_PropertyStore WHERE WorkId = $w AND ColumnId = $c";
            var w = lookup.Parameters.Add("$w", SqliteType.Integer);
            var c = lookup.Parameters.Add("$c", SqliteType.Integer);
            string? Get(long workId, long? column)
            {
                if (column is null) return null;
                w.Value = workId; c.Value = column;
                return lookup.ExecuteScalar() switch
                {
                    null or DBNull => null,
                    byte[] bytes => System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
                    var v => v.ToString(),
                } is { Length: > 0 } s ? s : null;
            }
            int withoutPath = 0;
            foreach (var (workId, id) in workIds)
            {
                var path = Get(workId, pathColumn)
                    ?? (Get(workId, folderColumn) is { } folder && Get(workId, nameColumn) is { } name ? Path.Combine(folder, name) : null)
                    ?? FromUrl(Get(workId, urlColumn));
                if (path is null) withoutPath++;
                else result[id] = path;
            }
            if (withoutPath > 0) _notes.Add($"{withoutPath} pictures are in the search index but without a file path.");
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode is 11 or 26)    // SQLITE_CORRUPT / SQLITE_NOTADB
        {
            _notes.Add("The Windows Search index looks damaged or is being rebuilt, so original file paths are shown as unknown. Try again later or use --full-index.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException || (ex is SqliteException s && s.SqliteErrorCode is 14 or 23))   // CANTOPEN / AUTH
        {
            _notes.Add("The Windows Search index can only be read with administrator rights. Run PCPorter as administrator to see original file paths.");
        }
        catch (Exception ex) when (ex is SqliteException or IOException)
        {
            _notes.Add($"The Windows Search index could not be read ({ex.Message.Split('\n')[0]}). Original file paths are shown as unknown.");
        }
        finally
        {
            if (copyDir is not null)
            {
                SqliteConnection.ClearAllPools();
                try { Directory.Delete(copyDir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        return result;
    }

    static string? FromUrl(string? url)
    {
        if (url is null) return null;
        if (url.StartsWith("file:", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(url, UriKind.Absolute, out var u)) return u.LocalPath;
        return url.Length > 2 && url[1] == ':' ? url : null;
    }

    static void CopyShared(string from, string to)
    {
        using var src = new FileStream(from, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan);
        using var dst = new FileStream(to, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20);
        src.CopyTo(dst, 1 << 20);
    }

    static SqliteConnection Open(string path, bool immutable)
    {
        var uri = "file:" + Uri.EscapeDataString(path.Replace('\\', '/')).Replace("%2F", "/").Replace("%3A", ":") + (immutable ? "?immutable=1" : "");
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = uri,
            Mode = immutable ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite,   // a private copy may need to replay its WAL
        }.ToString());
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA mmap_size=2147483648; PRAGMA cache_size=-262144; PRAGMA temp_store=MEMORY;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    static long? ColumnId(SqliteConnection conn, string propertyName)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id FROM SystemIndex_1_PropertyStore_Metadata WHERE Name = $n";
        cmd.Parameters.AddWithValue("$n", propertyName);
        return cmd.ExecuteScalar() is long id ? id : null;
    }

    sealed class NoteResolver(string note) : IThumbnailPathResolver
    {
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds) => new Dictionary<ulong, string>();
        public IReadOnlyList<string> Notes => [note];
    }
}
