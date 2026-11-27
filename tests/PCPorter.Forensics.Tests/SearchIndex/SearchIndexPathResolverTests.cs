using Microsoft.Data.Sqlite;
using PCPorter.Forensics.SearchIndex;

namespace PCPorter.Forensics.Tests.SearchIndex;

/// <summary>Uses a small synthetic database with the same layout as the Windows 11 index (verified on this PC).</summary>
public class SearchIndexPathResolverTests : IDisposable
{
    readonly string _db = Path.Combine(Path.GetTempPath(), $"pcporter-index-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        File.Delete(_db);
    }

    void Build(params (long WorkId, ulong CacheId, string? Path)[] rows)
    {
        using var conn = new SqliteConnection($"Data Source={_db}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE SystemIndex_1_PropertyStore_Metadata (Id INTEGER PRIMARY KEY, UniqueKey TEXT NOT NULL UNIQUE, Name TEXT NOT NULL,
              PropertyId INTEGER NOT NULL, VariantType INTEGER NOT NULL, StorageType INTEGER NOT NULL, MaxSize INTEGER, Flags INTEGER NOT NULL);
            CREATE TABLE SystemIndex_1_PropertyStore (WorkId INTEGER NOT NULL, ColumnId INTEGER NOT NULL, Value BLOB NOT NULL,
              PRIMARY KEY (WorkId, ColumnId)) WITHOUT ROWID;
            INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (33, '4448-System_ItemPathDisplay', 'System.ItemPathDisplay', 4448, 31, 11, 65536, 51);
            INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (352, '4683-System_ThumbnailCacheId', 'System.ThumbnailCacheId', 4683, 21, 12, 8, 54);
            """;
        cmd.ExecuteNonQuery();
        foreach (var (work, id, path) in rows)
        {
            using var ins = conn.CreateCommand();
            ins.CommandText = "INSERT INTO SystemIndex_1_PropertyStore VALUES ($w, 352, $v)";
            ins.Parameters.AddWithValue("$w", work);
            ins.Parameters.AddWithValue("$v", BitConverter.GetBytes(id));
            ins.ExecuteNonQuery();
            if (path is null) continue;
            ins.CommandText = "INSERT INTO SystemIndex_1_PropertyStore VALUES ($w, 33, $p)";
            ins.Parameters.AddWithValue("$p", path);
            ins.ExecuteNonQuery();
        }
    }

    [Fact]
    public void Resolves_only_requested_ids_to_paths()
    {
        Build((1, 0xAAUL, @"C:\Pics\cat.jpg"), (2, 0xBBUL, @"C:\Pics\dog.png"), (3, 0xCCUL, null));
        var map = new SearchIndexPathResolver(_db).Resolve([0xAAUL, 0xCCUL, 0xDDUL]);
        Assert.Equal(@"C:\Pics\cat.jpg", Assert.Single(map).Value);
        Assert.Equal(0xAAUL, map.Keys.Single());
    }

    [Fact]
    public void Copy_mode_gives_same_answer_and_cleans_up()
    {
        Build((1, 0xAAUL, @"C:\Pics\cat.jpg"));
        SqliteConnection.ClearAllPools();
        var work = Directory.CreateTempSubdirectory("pcporter-work").FullName;
        try
        {
            var map = new SearchIndexPathResolver(_db, copyToFolder: work).Resolve([0xAAUL]);
            Assert.Equal(@"C:\Pics\cat.jpg", map[0xAA]);
            Assert.Empty(Directory.EnumerateFileSystemEntries(work));
        }
        finally { Directory.Delete(work, true); }
    }

    [Fact]
    public void Falls_back_to_folder_and_name_when_full_path_is_missing()
    {
        Build((7, 0x77UL, null));
        using (var conn = new SqliteConnection($"Data Source={_db}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (40, '4449-System_ItemFolderPathDisplay', 'System.ItemFolderPathDisplay', 4449, 31, 11, 65536, 51);
                INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (41, '4450-System_ItemNameDisplay', 'System.ItemNameDisplay', 4450, 31, 11, 65536, 51);
                INSERT INTO SystemIndex_1_PropertyStore VALUES (7, 40, 'D:\Photos');
                INSERT INTO SystemIndex_1_PropertyStore VALUES (7, 41, 'beach.jpg');
                """;
            cmd.ExecuteNonQuery();
        }
        Assert.Equal(@"D:\Photos\beach.jpg", new SearchIndexPathResolver(_db).Resolve([0x77UL])[0x77]);
    }

    [Fact]
    public void Missing_index_gives_a_note_not_an_exception()
    {
        var resolver = new SearchIndexPathResolver(Path.Combine(Path.GetTempPath(), "does-not-exist", "Windows.db"));
        Assert.Empty(resolver.Resolve([1UL]));
        Assert.Single(resolver.Notes);
    }

    [Fact]
    public void Index_without_thumbnail_property_gives_a_note()
    {
        using (var conn = new SqliteConnection($"Data Source={_db}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "CREATE TABLE SystemIndex_1_PropertyStore_Metadata (Id INTEGER PRIMARY KEY, Name TEXT NOT NULL)";
            cmd.ExecuteNonQuery();
        }
        var resolver = new SearchIndexPathResolver(_db);
        Assert.Empty(resolver.Resolve([1UL]));
        Assert.Contains("does not record thumbnail ids", Assert.Single(resolver.Notes));
    }

    [Fact]
    public void Never_writes_to_the_index()
    {
        Build((1, 0xAAUL, @"C:\a.jpg"));
        SqliteConnection.ClearAllPools();
        var before = File.ReadAllBytes(_db);
        _ = new SearchIndexPathResolver(_db).Resolve([0xAAUL]);
        SqliteConnection.ClearAllPools();
        Assert.Equal(before, File.ReadAllBytes(_db));
    }
}
