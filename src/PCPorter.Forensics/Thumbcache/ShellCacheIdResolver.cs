using System.Runtime.InteropServices;

namespace PCPorter.Forensics.Thumbcache;

/// <summary>
/// Maps thumbnail cache ids to paths by asking Windows for the <c>System.ThumbnailCacheId</c> property of files and
/// folders that still exist (the approach Thumbcache Viewer uses). Reading the property never creates a thumbnail
/// and never writes anything. Only works on the running PC, for items whose name, location and contents are unchanged
/// since the thumbnail was made.
/// </summary>
public sealed class ShellCacheIdResolver(IEnumerable<string> roots, int maxItems = 300_000, TimeSpan? timeBudget = null) : IThumbnailPathResolver
{
    readonly List<string> _notes = [];
    public IReadOnlyList<string> Notes => _notes;

    static readonly HashSet<string> SkipFolders = new(StringComparer.OrdinalIgnoreCase)
        { "AppData", "$Recycle.Bin", "System Volume Information", "Windows", "Program Files", "Program Files (x86)", "ProgramData", "node_modules", ".git" };

    /// <summary>File types Explorer makes thumbnails for (pictures, video, PDFs, Office); folders are always checked.</summary>
    static readonly HashSet<string> ThumbnailTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".jfif", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".avif", ".tif", ".tiff", ".ico", ".svg",
        ".raw", ".cr2", ".cr3", ".nef", ".arw", ".dng", ".orf", ".rw2",
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".m4v", ".3gp", ".webm",
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".psd", ".mp3", ".m4a", ".flac",
    };

    /// <summary>The user's profile (without AppData), most likely folders first.</summary>
    public static ShellCacheIdResolver ForProfile(string profileFolder, TimeSpan? timeBudget = null)
    {
        string[] first = ["Pictures", "Desktop", "Downloads", "Documents", "Videos", Path.Combine("OneDrive", "Pictures"), Path.Combine("OneDrive", "Desktop"), Path.Combine("OneDrive", "Documents")];
        var roots = first.Select(f => Path.Combine(profileFolder, f)).Where(Directory.Exists).ToList();
        roots.Add(profileFolder);      // then everything else in the profile (already-visited folders are skipped)
        return new ShellCacheIdResolver(roots, timeBudget: timeBudget);
    }

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds)
        => Resolve(cacheIds, default);

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = new Dictionary<ulong, string>();
        if (cacheIds.Count == 0) return result;
        var wanted = cacheIds as ISet<ulong> ?? cacheIds.ToHashSet();
        var deadline = DateTime.UtcNow + (timeBudget ?? TimeSpan.FromMinutes(3));
        int visited = 0;
        bool stopped = false;

        // Shell objects are apartment-bound; use one STA thread for the whole walk. The thread only notes a cancel
        // (an exception on it would end the process); the caller's thread throws after Join.
        var thread = new Thread(() =>
        {
            var key = PKEY_ThumbnailCacheId;
            var iid = typeof(IShellItem2).GUID;
            foreach (var path in Walk(roots))
            {
                if (ct.IsCancellationRequested) break;
                if (++visited > maxItems || DateTime.UtcNow > deadline) { stopped = true; break; }
                if (SHCreateItemFromParsingName(path, IntPtr.Zero, ref iid, out var item) != 0 || item is null) continue;
                try
                {
                    if (item.GetUInt64(ref key, out var id) == 0 && id != 0 && wanted.Contains(id)) result.TryAdd(id, path);
                }
                finally { Marshal.ReleaseComObject(item); }
                if (result.Count == wanted.Count) break;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        thread.Join();
        ct.ThrowIfCancellationRequested();

        if (stopped) _notes.Add($"Stopped matching files to thumbnails after checking {visited:N0} items; some thumbnails may still show as unknown.");
        return result;
    }

    static IEnumerable<string> Walk(IEnumerable<string> roots)
    {
        var options = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System, RecurseSubdirectories = false };
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots.Where(Directory.Exists))
        {
            var stack = new Stack<string>([root]);
            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                if (!visited.Add(dir)) continue;
                List<FileSystemInfo> entries;
                try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos("*", options).ToList(); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
                foreach (var e in entries)
                {
                    if (e is DirectoryInfo d)
                    {
                        yield return d.FullName;                 // folders have thumbnails too
                        if (!SkipFolders.Contains(d.Name)) stack.Push(d.FullName);
                    }
                    else if (ThumbnailTypes.Contains(e.Extension)) yield return e.FullName;
                }
            }
        }
    }

    static PROPERTYKEY PKEY_ThumbnailCacheId => new(new Guid("446D16B1-8DAD-4870-A748-402EA43D788C"), 100);

    [StructLayout(LayoutKind.Sequential)]
    struct PROPERTYKEY(Guid fmtid, uint pid)
    {
        public Guid fmtid = fmtid;
        public uint pid = pid;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int SHCreateItemFromParsingName(string path, IntPtr bindCtx, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out IShellItem2? item);

    /// <summary>IShellItem2. Methods before GetUInt64 are declared only to keep the vtable order; they are never called.</summary>
    [ComImport, Guid("7e9fb0d3-919f-4307-ab2e-9b1860310c93"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IShellItem2
    {
        // IShellItem
        void BindToHandler(); void GetParent(); void GetDisplayName(); void GetAttributes(); void Compare();
        // IShellItem2
        void GetPropertyStore(); void GetPropertyStoreWithCreateObject(); void GetPropertyStoreForKeys();
        void GetPropertyDescriptionList(); void Update(); void GetProperty(); void GetCLSID(); void GetFileTime();
        void GetInt32(); void GetString(); void GetUInt32();
        [PreserveSig] int GetUInt64(ref PROPERTYKEY key, out ulong value);
    }
}
