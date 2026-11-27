using System.Security.Cryptography;
using System.Text;
using Microsoft.Isam.Esent.Interop;
using PCPorter.Forensics.SearchIndex;
using PCPorter.Forensics.Thumbcache;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.SearchIndex;

/// <summary>Runs only when this PC has a Windows 10 style search index (Windows.edb).</summary>
public sealed class LocalEseIndexFactAttribute : FactAttribute
{
    public const string Folder = @"C:\ProgramData\Microsoft\Search\Data\Applications\Windows";

    public LocalEseIndexFactAttribute()
    {
        if (!File.Exists(Path.Combine(Folder, EseSearchIndexPathResolver.DatabaseFileName)))
            Skip = "No Windows 10 search index (Windows.edb) on this PC.";
    }
}

/// <summary>
/// Builds a small synthetic ESE database with the Windows 10 index layout (table SystemIndex_PropertyStore,
/// columns "&lt;id&gt;-System_&lt;Property&gt;", logs with base name MSS) and resolves against it.
/// </summary>
public class EseSearchIndexPathResolverTests(ITestOutputHelper output) : IDisposable
{
    readonly string _root = Path.Combine(Path.GetTempPath(), $"pcporter-ese-{Guid.NewGuid():N}");
    string Index => Path.Combine(_root, "index");
    string Work => Path.Combine(_root, "work");

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    string Live => Path.Combine(_root, "live");

    /// <summary>
    /// Creates the database in a scratch folder and publishes it to <see cref="Index"/>. Dirty: a child process
    /// re-attaches the database and is killed without shutting ESE down (a real crash, like copying a live
    /// index), so the copy is in dirty-shutdown state and needs log replay. ESE holds a live database and its
    /// current log exclusively, so the crash happens before the files are copied.
    /// </summary>
    void Build(bool withPath, bool dirty, params (int WorkId, ulong CacheId, string? Path)[] rows)
    {
        Directory.CreateDirectory(Live);
        Directory.CreateDirectory(Work);
        CreateDatabase(withPath, rows);
        if (dirty) CrashWhileAttached();
        Directory.CreateDirectory(Index);
        foreach (var f in Directory.EnumerateFiles(Live)) File.Copy(f, Path.Combine(Index, Path.GetFileName(f)));
    }

    void CreateDatabase(bool withPath, (int WorkId, ulong CacheId, string? Path)[] rows)
    {
        using var instance = new Instance($"pcporter-test-{Guid.NewGuid():N}");
        instance.Parameters.SystemDirectory = Live + "\\";
        instance.Parameters.LogFileDirectory = Live + "\\";
        instance.Parameters.TempDirectory = Live + "\\";
        instance.Parameters.BaseName = "MSS";
        instance.Parameters.LogFileSize = 1024;
        instance.Parameters.NoInformationEvent = true;
        instance.Init();
        using var session = new Session(instance);
        var db = Path.Combine(Live, EseSearchIndexPathResolver.DatabaseFileName);
        Api.JetCreateDatabase(session, db, null, out var dbid, CreateDatabaseGrbit.None);
        JET_TABLEID table;
        JET_COLUMNID workCol, idCol, pathCol = JET_COLUMNID.Nil;
        using (var tx = new Transaction(session))
        {
            Api.JetCreateTable(session, dbid, "SystemIndex_PropertyStore", 0, 100, out table);
            Api.JetAddColumn(session, table, "WorkID", new JET_COLUMNDEF { coltyp = JET_coltyp.Long }, null, 0, out workCol);
            Api.JetAddColumn(session, table, "4683-System_ThumbnailCacheId", new JET_COLUMNDEF { coltyp = JET_coltyp.Binary, cbMax = 8 }, null, 0, out idCol);
            if (withPath)
                Api.JetAddColumn(session, table, "4448-System_ItemPathDisplay", new JET_COLUMNDEF { coltyp = JET_coltyp.LongText, cp = JET_CP.Unicode }, null, 0, out pathCol);
            tx.Commit(CommitTransactionGrbit.None);
        }
        foreach (var (work, id, path) in rows)
        {
            using var tx = new Transaction(session);
            using (var update = new Update(session, table, JET_prep.Insert))
            {
                Api.SetColumn(session, table, workCol, work);
                Api.SetColumn(session, table, idCol, BitConverter.GetBytes(id));
                if (withPath && path is not null) Api.SetColumn(session, table, pathCol, path, Encoding.Unicode);
                update.Save();
            }
            tx.Commit(CommitTransactionGrbit.None);
        }
        Api.JetCloseTable(session, table);
        Api.JetCloseDatabase(session, dbid, CloseDatabaseGrbit.None);
        Api.JetDetachDatabase(session, db);
    }

    /// <summary>Windows PowerShell P/Invokes esent.dll: JetInit, attach, then kills itself without JetTerm.</summary>
    void CrashWhileAttached()
    {
        Api.JetGetDatabaseFileInfo(Path.Combine(Live, EseSearchIndexPathResolver.DatabaseFileName), out int pageSize, JET_DbInfo.PageSize);
        const string Script = """
            param($dir, $pageSize)
            Add-Type -TypeDefinition @'
            using System; using System.Runtime.InteropServices;
            public static class J {
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetCreateInstanceW(out IntPtr i, string n);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetSetSystemParameterW(ref IntPtr i, IntPtr s, int p, IntPtr l, string v);
              [DllImport("esent.dll")] public static extern int JetInit(ref IntPtr i);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetBeginSessionW(IntPtr i, out IntPtr s, string u, string p);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetAttachDatabaseW(IntPtr s, string f, int g);
            }
            '@
            $i = [IntPtr]::Zero; $s = [IntPtr]::Zero; $z = [IntPtr]::Zero
            $rc = @()
            $rc += [J]::JetSetSystemParameterW([ref]$z, $z, 64, [IntPtr][int]$pageSize, $null)
            $rc += [J]::JetCreateInstanceW([ref]$i, 'pcporter-crash')
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 0, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 1, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 2, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 3, $z, 'MSS')
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 11, [IntPtr]1024, $null)
            $rc += [J]::JetInit([ref]$i)
            $rc += [J]::JetBeginSessionW($i, [ref]$s, '', '')
            $rc += [J]::JetAttachDatabaseW($s, "$dir\Windows.edb", 0)
            [Console]::Out.WriteLine(($rc -join ','))
            [Console]::Out.Flush()
            [Diagnostics.Process]::GetCurrentProcess().Kill()
            """;
        var scriptPath = Path.Combine(_root, "crash.ps1");
        File.WriteAllText(scriptPath, Script);
        var psi = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, Live, pageSize.ToString() })
            psi.ArgumentList.Add(a);
        using var p = System.Diagnostics.Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(60_000), "crash helper hung");
        output.WriteLine($"crash helper: {stdout.Trim()}");
        // Each JET call returned 0 (warnings are positive and fine).
        Assert.Matches(@"^(-?\d+,){9}-?\d+", stdout.Trim());
        Assert.DoesNotContain("-", stdout.Trim().Split('\n')[0]);
    }


    Dictionary<string, string> Snapshot() =>
        Directory.EnumerateFiles(Index).ToDictionary(f => Path.GetFileName(f), f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));

    static readonly (int, ulong, string?)[] Rows =
        [(1, 0xAAUL, @"C:\Pics\cat.jpg"), (2, 0xBBUL, @"C:\Pics\dog.png"), (3, 0xCCUL, null), (4, 0x1122334455667788UL, @"D:\Fotos\übung.jpg")];

    [Fact]
    public void Resolves_only_requested_ids_to_paths()
    {
        Build(withPath: true, dirty: false, Rows);
        var resolver = new EseSearchIndexPathResolver(Index, Work);
        var map = resolver.Resolve([0xAAUL, 0xCCUL, 0xDDUL, 0x1122334455667788UL]);
        Assert.Equal(2, map.Count);
        Assert.Equal(@"C:\Pics\cat.jpg", map[0xAAUL]);
        Assert.Equal(@"D:\Fotos\übung.jpg", map[0x1122334455667788UL]);
        Assert.Empty(resolver.Notes);
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    [Fact]
    public void Big_endian_ids_are_matched_too()
    {
        Build(withPath: true, dirty: false, Rows);
        var map = new EseSearchIndexPathResolver(Index, Work).Resolve([0x8877665544332211UL]);
        Assert.Equal(@"D:\Fotos\übung.jpg", Assert.Single(map).Value);
    }

    [Theory]
    [InlineData(EseRecoveryMode.EngineThenEsentutl)]
    [InlineData(EseRecoveryMode.EsentutlOnly)]
    public void Dirty_index_is_recovered_on_the_copy_and_originals_are_never_written(EseRecoveryMode mode)
    {
        Build(withPath: true, dirty: true, Rows);
        Api.JetGetDatabaseFileInfo(Path.Combine(Index, EseSearchIndexPathResolver.DatabaseFileName), out JET_DBINFOMISC info, JET_DbInfo.Misc);
        Assert.Equal(JET_dbstate.DirtyShutdown, info.dbstate);
        var before = Snapshot();

        var steps = new Steps();
        var resolver = new EseSearchIndexPathResolver(Index, Work, steps, mode);
        var map = resolver.Resolve([0xAAUL, 0xBBUL]);

        Assert.True(map.Count == 2, string.Join(" | ", resolver.Notes));
        Assert.Equal(@"C:\Pics\dog.png", map[0xBBUL]);
        Assert.Contains(steps.Messages, m => m.StartsWith("Repairing the copy"));
        // The in-process engine recovery must succeed on its own; esentutl is only the fallback.
        Assert.Equal(mode == EseRecoveryMode.EsentutlOnly, steps.Messages.Any(m => m.EndsWith("with esentutl")));
        Assert.Equal(before, Snapshot());
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    sealed class Steps : IProgress<string>
    {
        public List<string> Messages { get; } = [];
        public void Report(string value) => Messages.Add(value);
    }

    [Fact]
    public void Clean_index_is_never_written()
    {
        Build(withPath: true, dirty: false, Rows);
        var before = Snapshot();
        _ = new EseSearchIndexPathResolver(Index, Work).Resolve([0xAAUL]);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public void Missing_path_column_gives_a_note()
    {
        Build(withPath: false, dirty: false, Rows);
        var resolver = new EseSearchIndexPathResolver(Index, Work);
        Assert.Empty(resolver.Resolve([0xAAUL]));
        Assert.Contains("does not record original paths", Assert.Single(resolver.Notes));
    }

    [Fact]
    public void Missing_index_gives_a_note_not_an_exception()
    {
        var resolver = new EseSearchIndexPathResolver(Path.Combine(_root, "does-not-exist"), Work);
        Assert.Empty(resolver.Resolve([1UL]));
        Assert.Single(resolver.Notes);
    }

    [Fact]
    public void Corrupt_index_gives_a_note_not_an_exception()
    {
        Directory.CreateDirectory(Index);
        Directory.CreateDirectory(Work);
        File.WriteAllBytes(Path.Combine(Index, EseSearchIndexPathResolver.DatabaseFileName), new byte[8192]);
        var resolver = new EseSearchIndexPathResolver(Index, Work);
        Assert.Empty(resolver.Resolve([1UL]));
        Assert.Single(resolver.Notes);
        Assert.Empty(Directory.EnumerateFileSystemEntries(Work));
    }

    [Fact]
    public void Factory_picks_the_reader_from_the_files_present()
    {
        Build(withPath: true, dirty: false, Rows);
        Assert.IsType<EseSearchIndexPathResolver>(SearchIndexResolverFactory.ForPc(Index, Work));
        var none = SearchIndexResolverFactory.ForPc(Work, Work);
        Assert.Empty(none.Resolve([0xAAUL]));
        Assert.Single(none.Notes);
    }

    [Fact]
    public void Decodes_plain_and_7bit_text_and_rejects_garbage()
    {
        Assert.Equal(@"C:\a.jpg", EseSearchIndexPathResolver.DecodeText(Encoding.Unicode.GetBytes(@"C:\a.jpg" + "\0")));
        Assert.Equal(@"C:\a.jpg", EseSearchIndexPathResolver.DecodeText(Pack7Bit(0x10, @"C:\a.jpg")));
        Assert.Null(EseSearchIndexPathResolver.DecodeText([0x18, 0x01, 0x02, 0x00, 0xFF]));
        Assert.Null(EseSearchIndexPathResolver.DecodeText([0x41, 0x00, 0x01]));
    }

    static byte[] Pack7Bit(byte header, string s)
    {
        var bytes = new List<byte> { header };
        uint bits = 0;
        int n = 0;
        foreach (var c in s)
        {
            bits |= (uint)(c & 0x7F) << n;
            n += 7;
            while (n >= 8) { bytes.Add((byte)bits); bits >>= 8; n -= 8; }
        }
        if (n > 0) bytes.Add((byte)bits);
        return [.. bytes];
    }

    [LocalEseIndexFact, Trait("Category", "Live")]
    public void Resolves_against_this_pcs_windows10_index()
    {
        var ids = new HashSet<ulong>();
        foreach (var path in Directory.EnumerateFiles(Thumbcache.LocalThumbcacheFactAttribute.Folder, "thumbcache_*.db"))
        {
            if (path.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) continue;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var bytes = new byte[fs.Length];
            fs.ReadExactly(bytes);
            if (bytes.Length == 0) continue;
            foreach (var e in ThumbcacheParser.Parse(bytes, Path.GetFileName(path)).Entries) ids.Add(e.CacheId);
        }
        var resolver = new EseSearchIndexPathResolver(LocalEseIndexFactAttribute.Folder, Path.GetTempPath());
        var map = resolver.Resolve(ids);
        output.WriteLine($"{ids.Count} cache ids, {map.Count} resolved. Notes: {string.Join(" | ", resolver.Notes)}");
    }
}
