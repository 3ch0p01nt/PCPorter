using PCPorter.Collectors.Sources;
using PCPorter.Core.IO;

namespace PCPorter.Collectors;

public enum Presence
{
    /// <summary>Exists inside the scanned drive, reached through no link.</summary>
    Present,
    /// <summary>Not there (a folder on the way is missing, before any link).</summary>
    Missing,
    /// <summary>Reached through a link (junction, symlink, mount point) or outside the scanned drive: not followed, so unknown.</summary>
    NotFollowed,
}

/// <summary>
/// "Does this file exist?" for paths on the scanned drive, answered WITHOUT following links: File.Exists and
/// Directory.Exists follow a junction or symlink planted on an old drive, which can point at a network share and leak
/// the user's sign-in (NTLM) just by being looked at. Use this (or <see cref="SourceFiles"/>) instead of them for any
/// path that comes from the scanned PC. Outside <see cref="SourceFiles.Confine"/> (unit tests) it is a plain check.
/// </summary>
public static class SourcePresence
{
    public static Presence Of(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return Presence.Missing;
        try
        {
            if (SourceFiles.IsInside(path))   // under confinement this already means "exists, no link on the way"
                return File.Exists(path) || Directory.Exists(path) ? Presence.Present : Presence.Missing;
            return MissingBeforeAnyLink(path) ? Presence.Missing : Presence.NotFollowed;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return Presence.NotFollowed;
        }
    }

    /// <summary>True when the path exists as a file inside the scanned drive (no link on the way).</summary>
    public static bool IsFile(string? path) => Of(path) == Presence.Present && File.Exists(path);

    /// <summary>True when the path exists as a folder inside the scanned drive (no link on the way).</summary>
    public static bool IsFolder(string? path) => Of(path) == Presence.Present && Directory.Exists(path);

    /// <summary>
    /// Walks from the drive root, opening each entry itself (links not followed): true at the first missing entry,
    /// false at the first link (the path may well exist behind it) or when every entry exists.
    /// </summary>
    static bool MissingBeforeAnyLink(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal)) return false;   // never touch the network
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full);
        if (root is not { Length: 3 } || root[1] != ':') return false;
        var current = root;
        foreach (var part in full[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            var entry = FileIdentity.Entry(current);
            if (entry is null) return true;
            if (entry.Value.IsLink) return false;
        }
        return false;
    }
}
