using System.Buffers.Binary;
using System.ComponentModel;
using System.Text;
using Microsoft.Isam.Esent;
using Microsoft.Isam.Esent.Interop;
using PCPorter.Forensics.Ese;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.SearchIndex;

/// <summary>How a copied index in dirty-shutdown state is brought to a clean state before it is read.</summary>
public enum EseRecoveryMode
{
    /// <summary>Replay the copied logs with the ESE engine in-process; fall back to esentutl if that fails.</summary>
    EngineThenEsentutl,
    /// <summary>Only use <c>esentutl /r</c> on the copy.</summary>
    EsentutlOnly,
}

/// <summary>
/// Maps thumbnail cache ids to original paths using the Windows 10 search index (Windows.edb, ESE).
/// The originals are never opened for writing: Windows.edb and its MSS* logs are copied (shared read) into a
/// private work folder, recovery (if the copy is in dirty-shutdown state) runs on the copy only, with database
/// recovery redirected to the copy folder, and the copy is attached read-only and deleted afterwards.
/// Layout: table SystemIndex_PropertyStore (SystemIndex_0A on old builds), one row per item, columns named
/// "&lt;id&gt;-System_&lt;Property&gt;" (e.g. 4683-System_ThumbnailCacheId = 8-byte blob,
/// 4448-System_ItemPathDisplay = text).
/// </summary>
public sealed class EseSearchIndexPathResolver(
    string indexFolder,
    string workFolder,
    IProgress<string>? progress = null,
    EseRecoveryMode recoveryMode = EseRecoveryMode.EngineThenEsentutl) : IThumbnailPathResolver
{
    public const string DatabaseFileName = "Windows.edb";
    const string LogBaseName = "MSS";
    static readonly string[] TableNames = ["SystemIndex_PropertyStore", "SystemIndex_0A"];
    static readonly string[] CopyPatterns = [DatabaseFileName, LogBaseName + "*.log", LogBaseName + "*.jrs", LogBaseName + "*.chk"];

    readonly List<string> _notes = [];
    public IReadOnlyList<string> Notes => _notes;

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds)
    {
        var result = new Dictionary<ulong, string>();
        if (cacheIds.Count == 0) return result;
        var wanted = cacheIds as ISet<ulong> ?? cacheIds.ToHashSet();

        if (!File.Exists(Path.Combine(indexFolder, DatabaseFileName)))
        {
            _notes.Add("No Windows 10 search index was found (or it is not readable without administrator rights). Original file paths are shown as unknown.");
            return result;
        }

        var copy = Path.Combine(workFolder, $"pcporter-edb-{Guid.NewGuid():N}");
        try
        {
            progress?.Report("Copying the Windows search index");
            if (!CopyIndex(copy, out var skipped)) return result;
            var db = Path.Combine(copy, DatabaseFileName);

            Api.JetGetDatabaseFileInfo(db, out JET_DBINFOMISC info, JET_DbInfo.Misc);
            SetPageSize(info.cbPageSize);
            if (info.dbstate == JET_dbstate.DirtyShutdown && !Recover(copy, db, skipped)) return result;

            progress?.Report("Reading the search index (this can take a few minutes on large indexes)");
            Read(copy, db, wanted, result);
        }
        catch (Exception ex) when (ex is EsentException or IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            _notes.Add($"The Windows Search index could not be read ({ex.Message.Split('\n')[0].Trim()}). Original file paths are shown as unknown.");
        }
        finally
        {
            TryDeleteFolder(copy);
        }
        return result;
    }

    /// <summary>Copies the database and its logs with shared reads (the Search service may hold them open).</summary>
    bool CopyIndex(string copy, out List<string> skipped)
    {
        skipped = [];
        Directory.CreateDirectory(copy);
        foreach (var pattern in CopyPatterns)
        {
            foreach (var source in Directory.EnumerateFiles(indexFolder, pattern))
            {
                var name = Path.GetFileName(source);
                try
                {
                    using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var output = new FileStream(Path.Combine(copy, name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    input.CopyTo(output);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    if (name.Equals(DatabaseFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        _notes.Add("The Windows 10 search index is in use or protected and could not be copied. " +
                                   "Run PCPorter as administrator, or read it from a shadow copy, to see original file paths.");
                        return false;
                    }
                    skipped.Add(name);
                }
            }
        }
        return true;
    }

    /// <summary>Replays the copied logs so the copied database reaches a clean state. Only the copy folder is used.</summary>
    bool Recover(string copy, string db, List<string> skipped)
    {
        progress?.Report("Repairing the copy of the search index");
        string? error = null;
        if (recoveryMode == EseRecoveryMode.EngineThenEsentutl)
        {
            error = EseCopy.RecoverWithEngine(copy, LogBaseName, DisplayName);
            if (EseCopy.IsClean(db)) return true;
        }

        progress?.Report("Repairing the copy of the search index with esentutl");
        error = EseCopy.RunEsentutl(copy, LogBaseName) ?? error;
        if (EseCopy.IsClean(db)) return true;

        var missing = skipped.Count > 0 ? $" Some log files could not be copied ({string.Join(", ", skipped)})." : "";
        _notes.Add($"The copy of the Windows 10 search index could not be repaired ({error ?? "unknown error"}).{missing} " +
                   "Run PCPorter as administrator, or read it from a shadow copy, to see original file paths.");
        return false;
    }

    void Read(string copy, string db, ISet<ulong> wanted, Dictionary<ulong, string> result)
    {
        using var instance = CreateInstance(copy, recovery: false);
        instance.Init();
        using var session = new Session(instance);
        Api.JetAttachDatabase(session, db, AttachDatabaseGrbit.ReadOnly);
        try
        {
            Api.JetOpenDatabase(session, db, null, out var dbid, OpenDatabaseGrbit.ReadOnly);
            try { ReadTable(session, dbid, wanted, result); }
            finally { Api.JetCloseDatabase(session, dbid, CloseDatabaseGrbit.None); }
        }
        finally
        {
            Api.JetDetachDatabase(session, db);
        }
    }

    void ReadTable(Session session, JET_DBID dbid, ISet<ulong> wanted, Dictionary<ulong, string> result)
    {
        var tables = Api.GetTableNames(session, dbid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var table = TableNames.FirstOrDefault(tables.Contains);
        if (table is null)
        {
            _notes.Add("The Windows 10 search index has no property table PCPorter recognizes. Original file paths are shown as unknown.");
            return;
        }

        var columns = Api.GetTableColumns(session, dbid, table).ToList();
        var idColumn = Find(columns, "System_ThumbnailCacheId");
        if (idColumn is null)
        {
            _notes.Add("The search index does not record thumbnail ids on this PC. Original file paths are shown as unknown.");
            return;
        }
        var pathColumn = Find(columns, "System_ItemPathDisplay");
        var folderColumn = Find(columns, "System_ItemFolderPathDisplay");
        var nameColumn = Find(columns, "System_ItemNameDisplay");
        var urlColumn = Find(columns, "System_ItemUrl");
        if (pathColumn is null && (folderColumn is null || nameColumn is null) && urlColumn is null)
        {
            _notes.Add("The search index does not record original paths on this PC. Original file paths are shown as unknown.");
            return;
        }

        int undecodable = 0;
        Api.JetOpenTable(session, dbid, table, null, 0, OpenTableGrbit.ReadOnly | OpenTableGrbit.Sequential, out var tableid);
        try
        {
            if (!Api.TryMoveFirst(session, tableid)) return;
            do
            {
                if (Api.RetrieveColumn(session, tableid, idColumn.Columnid) is not { Length: 8 } raw) continue;
                var le = BinaryPrimitives.ReadUInt64LittleEndian(raw);
                var be = BinaryPrimitives.ReadUInt64BigEndian(raw);
                ulong id;
                if (wanted.Contains(le)) id = le;
                else if (wanted.Contains(be)) id = be;
                else continue;
                if (result.ContainsKey(id)) continue;

                bool sawUnreadable = false;
                string? Text(ColumnInfo? c)
                {
                    if (c is null || Api.RetrieveColumn(session, tableid, c.Columnid) is not { Length: > 0 } bytes) return null;
                    var t = DecodeText(bytes, c.Cp == JET_CP.ASCII);
                    if (t is null) sawUnreadable = true;
                    return t;
                }

                var path = Text(pathColumn);
                if (path is null && Text(folderColumn) is { } folder && Text(nameColumn) is { } name) path = Path.Combine(folder, name);
                if (path is null && Text(urlColumn) is { } url) path = FromItemUrl(url);
                if (path is not null) result[id] = path;
                else if (sawUnreadable) undecodable++;
            }
            while (Api.TryMoveNext(session, tableid));
        }
        finally
        {
            Api.JetCloseTable(session, tableid);
        }

        if (undecodable > 0)
            _notes.Add($"{undecodable} original path(s) in the Windows 10 search index are stored in a compressed format PCPorter cannot read yet; they are shown as unknown.");
    }

    static ColumnInfo? Find(List<ColumnInfo> columns, string suffix) =>
        columns.FirstOrDefault(c => c.Name.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
                                    c.Name.EndsWith("-" + suffix, StringComparison.OrdinalIgnoreCase));

    /// <summary>"file:C:/Users/a/b.jpg" -> "C:\Users\a\b.jpg". Other schemes are returned unchanged.</summary>
    static string FromItemUrl(string url) =>
        url.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ? url["file:".Length..].TrimStart('/').Replace('/', '\\') : url;

    /// <summary>
    /// Decodes a text value from the index. The engine already undoes ESE's own column compression on retrieval,
    /// so values are normally plain UTF-16 (or ANSI for ASCII columns). Raw ESE 7-bit compressed values
    /// (header byte 0x08 = 7-bit ASCII, 0x10 = 7-bit Unicode) are also decoded. Anything else (e.g. 0x18 Xpress,
    /// or Windows Search's own string compression) returns null.
    /// </summary>
    public static string? DecodeText(byte[] value, bool ansi = false)
    {
        if (value.Length == 0) return null;
        if ((value[0] >> 3) is 1 or 2 && Decode7Bit(value) is { } seven && IsPlausible(seven)) return seven;
        if (ansi)
        {
            var a = Encoding.Latin1.GetString(value).TrimEnd('\0');
            return IsPlausible(a) ? a : null;
        }
        if (value.Length % 2 != 0) return null;
        var u = Encoding.Unicode.GetString(value).TrimEnd('\0');
        return IsPlausible(u) ? u : null;
    }

    /// <summary>ESE 7-bit compression: one header byte, then 7-bit characters packed least-significant bit first.</summary>
    static string? Decode7Bit(byte[] value)
    {
        var count = (value.Length - 1) * 8 / 7;
        if (count == 0) return null;
        var sb = new StringBuilder(count);
        uint bits = 0;
        int nbits = 0;
        for (int i = 1; i < value.Length && sb.Length < count; i++)
        {
            bits |= (uint)value[i] << nbits;
            nbits += 8;
            while (nbits >= 7 && sb.Length < count)
            {
                sb.Append((char)(bits & 0x7F));
                bits >>= 7;
                nbits -= 7;
            }
        }
        return sb.ToString().TrimEnd('\0');
    }

    static bool IsPlausible(string s)
    {
        if (s.Length == 0) return false;
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c < 0x20 || c == '\uFFFD') return false;
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(c)) return false;
        }
        return true;
    }

    const string DisplayName = "PCPorter search index reader";

    static Instance CreateInstance(string copy, bool recovery) => EseCopy.CreateInstance(copy, LogBaseName, recovery, DisplayName);

    static void SetPageSize(int pageSize) => EseCopy.SetPageSize(pageSize);

    static void TryDeleteFolder(string folder) => EseCopy.TryDeleteFolder(folder);
}
