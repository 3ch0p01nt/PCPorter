namespace PCPorter.Forensics.Gallery;

public sealed record FileTimes(DateTimeOffset CreatedUtc, DateTimeOffset ModifiedUtc);

/// <summary>Filesystem questions the locator needs; swapped for a fake in tests.</summary>
public interface IFileProbe
{
    bool DriveAvailable(string root);
    /// <summary>Names in the folder (case-insensitive), null if the folder does not exist; throws UnauthorizedAccessException if denied.</summary>
    IReadOnlySet<string>? List(string folder);
    FileTimes? Times(string path);
}

public sealed class RealFileProbe : IFileProbe
{
    public bool DriveAvailable(string root)
    {
        try { return new DriveInfo(root).IsReady; }
        catch (ArgumentException) { return Directory.Exists(root); }
    }

    public IReadOnlySet<string>? List(string folder)
    {
        if (!Directory.Exists(folder)) return null;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in Directory.EnumerateFileSystemEntries(folder)) names.Add(Path.GetFileName(e));
        return names;
    }

    public FileTimes? Times(string path)
    {
        try
        {
            var info = File.Exists(path) ? (FileSystemInfo)new FileInfo(path) : new DirectoryInfo(path);
            return info.Exists ? new FileTimes(info.CreationTimeUtc, info.LastWriteTimeUtc) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}

/// <summary>
/// Decides Exists / Deleted / Unreachable for original paths. Lists each folder once (fast for thousands of items)
/// and only says "Deleted" when the containing folder could be read and the item is not in it.
/// </summary>
public sealed class OriginalLocator(IFileProbe? probe = null)
{
    readonly IFileProbe _probe = probe ?? new RealFileProbe();
    readonly Dictionary<string, (IReadOnlySet<string>? Names, bool Denied)> _folders = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, bool> _drives = new(StringComparer.OrdinalIgnoreCase);

    public OriginalStatus Locate(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return OriginalStatus.Unknown;
        string? root, parent, name;
        try
        {
            root = Path.GetPathRoot(path);
            parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(path));
            name = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
        }
        catch (ArgumentException) { return OriginalStatus.Unknown; }
        if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(parent) || string.IsNullOrEmpty(name)) return OriginalStatus.Unknown;

        if (!_drives.TryGetValue(root, out var available)) _drives[root] = available = SafeDrive(root);
        if (!available) return OriginalStatus.Unreachable;

        var (names, denied) = Folder(parent);
        if (denied) return OriginalStatus.Unreachable;
        if (names is not null) return names.Contains(name) ? OriginalStatus.Exists : OriginalStatus.Deleted;

        // The folder itself is gone: deleted, unless an ancestor could not be read.
        for (var up = Path.GetDirectoryName(parent); !string.IsNullOrEmpty(up); up = Path.GetDirectoryName(up))
        {
            var (upNames, upDenied) = Folder(up);
            if (upDenied) return OriginalStatus.Unreachable;
            if (upNames is not null) return OriginalStatus.Deleted;
        }
        return OriginalStatus.Unreachable;
    }

    public FileTimes? Times(string path) => _probe.Times(path);

    (IReadOnlySet<string>? Names, bool Denied) Folder(string folder)
    {
        if (_folders.TryGetValue(folder, out var cached)) return cached;
        (IReadOnlySet<string>?, bool) result;
        try { result = (_probe.List(folder), false); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { result = (null, true); }
        _folders[folder] = result;
        return result;
    }

    bool SafeDrive(string root)
    {
        try { return _probe.DriveAvailable(root); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}
