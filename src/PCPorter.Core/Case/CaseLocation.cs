using Microsoft.Win32;
using PCPorter.Core.IO;

namespace PCPorter.Core.Case;

public sealed record CaseLocationResult(bool IsAllowed, string? Reason);

/// <summary>
/// Case files hold browsing history, images and passwords: never let them land in a cloud-synced or network folder,
/// or on the drive being checked. The checks run on where the folder REALLY is: subst drive letters are resolved
/// (QueryDosDevice), existing folders are opened without following links (any junction, symlink, mount point or
/// cloud-files placeholder on the way is refused), and the real path is compared with every registered sync root
/// (Windows SyncRootManager for all accounts, OneDrive's own account folders and SharePoint/Teams libraries).
/// </summary>
public static class CaseLocation
{
    const string PickLocal = "Pick the backup drive or a local folder.";
    const string NetworkReason = "Network folders are not allowed. " + PickLocal;
    const string OnScannedDrive = "Save the report somewhere other than the drive being checked, so nothing is written to it.";

    static readonly string[] EnvRoots = ["OneDrive", "OneDriveCommercial", "OneDriveConsumer"];
    static readonly string[] SyncedFolderNames = ["Dropbox", "Google Drive", "iCloudDrive", "Box"];

    /// <summary>Whether a case may be saved in <paramref name="path"/> (cloud-synced, network and unusable paths are refused).</summary>
    public static CaseLocationResult Check(string path, Func<string, string?>? getEnv = null) =>
        Check(path, getEnv ?? Environment.GetEnvironmentVariable, WindowsProbe.Instance, scannedRoot: null);

    /// <summary>
    /// As <see cref="Check(string, Func{string, string?}?)"/>, and also refuses a folder on the drive (or inside the
    /// folder) being scanned, <paramref name="scannedRoot"/>, however either is reached (subst letter, mount point,
    /// \\?\ or device path): the real NT locations are compared. Pass null for a scan of this PC.
    /// </summary>
    public static CaseLocationResult Check(string path, string? scannedRoot, Func<string, string?>? getEnv = null) =>
        Check(path, getEnv ?? Environment.GetEnvironmentVariable, WindowsProbe.Instance, scannedRoot);

    internal static CaseLocationResult Check(string path, Func<string, string?> getEnv, ILocationProbe probe, string? scannedRoot)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            return No(@"Pick a full folder path, for example E:\PCPorter.");
        string full;
        try { full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        { return No("That is not a valid folder path. Pick the backup drive or a local folder."); }

        if (full.StartsWith(@"\\?\", StringComparison.Ordinal) || full.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            var rest = full[4..];
            if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase)) return No(NetworkReason);
            if (!IsDrivePath(rest)) return No(@"Pick a folder on a drive letter, for example E:\PCPorter.");
            full = rest;                                    // \\?\D:\long\path is an ordinary local path
        }
        if (full.StartsWith(@"\\", StringComparison.Ordinal) || !IsDrivePath(full)) return No(NetworkReason);
        if (full.Length == 2) full += "\\";

        // Resolve subst letters (a subst chain is short; the hop limit stops a loop).
        for (int hop = 0; ; hop++)
        {
            if (Lexical(full, getEnv) is { } why) return No(why);
            var root = full[..3];
            var type = probe.DriveType(root);
            if (type == DriveType.Network) return No(NetworkReason);
            if (type == DriveType.NoRootDirectory) return No($"Drive {full[..2]} was not found. {PickLocal}");
            var target = probe.DosDeviceTarget(full[..2]);
            if (target is not null && IsNetworkDevice(target)) return No(NetworkReason);
            if (target is null || !target.StartsWith(@"\??\", StringComparison.Ordinal)) break;
            var substituted = target[4..];
            if (substituted.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase)) return No(NetworkReason);
            if (!IsDrivePath(substituted) || hop >= 8) return No("PCPorter could not check where this folder really is. " + PickLocal);
            full = Path.TrimEndingDirectorySeparator(Path.Join(substituted, full[3..]));
            if (full.Length == 2) full += "\\";
        }

        // A write-protect switch (SD cards, some sticks) or a read-only mount: say so now, not after a failed save.
        if (probe.IsReadOnlyVolume(full[..3]) == true)
            return No($"Drive {full[..2]} is write-protected (read-only), so nothing can be saved on it. Turn off its write-protect switch, or pick another drive.");

        var volume = probe.Volume(full[..3]);
        if (volume.Label?.Contains("Google Drive", StringComparison.OrdinalIgnoreCase) == true
            || (string.Equals(volume.FileSystem, "FAT32", StringComparison.OrdinalIgnoreCase) && probe.Entry(full[..3] + "My Drive") is not null)
            || string.Equals(volume.FileSystem, "GoogleDriveFS", StringComparison.OrdinalIgnoreCase))
            return No($"Drive {full[..2]} looks like Google Drive (cloud-synced). {PickLocal}");

        if (ChainProblem(full, probe, out var deepest) is { } chain) return No(chain);
        if (deepest is null) return No("PCPorter could not check where this folder really is. " + PickLocal);
        var tail = full.Length > deepest.Length ? full[deepest.Length..].TrimStart('\\') : "";

        // No link on the way, but the real path is checked again in case the ancestor itself is reached another way.
        var real = probe.FinalPath(deepest);
        if (real is null) return No("PCPorter could not check where this folder really is. " + PickLocal);
        if (real.StartsWith(@"\\", StringComparison.Ordinal)) return No(NetworkReason);
        var realFull = Path.TrimEndingDirectorySeparator(tail.Length == 0 ? real : Path.Join(real, tail));
        if (!realFull.Equals(full, StringComparison.OrdinalIgnoreCase))
        {
            if (!IsDrivePath(realFull)) return No("PCPorter could not check where this folder really is. " + PickLocal);
            if (Lexical(realFull, getEnv) is { } why) return No(why);
            if (probe.DriveType(realFull[..3]) == DriveType.Network) return No(NetworkReason);
        }

        foreach (var syncRoot in probe.SyncRoots())
            if (IsUnder(full, syncRoot) || IsUnder(realFull, syncRoot))
                return No($"This folder is cloud-synced ({syncRoot}). {PickLocal}");

        if (scannedRoot is not null)
        {
            var scanNt = probe.NtPath(scannedRoot.EndsWith('\\') ? scannedRoot : scannedRoot + "\\");
            var saveNt = probe.NtPath(deepest);
            if (scanNt is null || saveNt is null)
                return No("PCPorter could not check whether this folder is on the drive being checked. Pick a folder on another drive.");
            if (IsUnder(tail.Length == 0 ? saveNt : saveNt.TrimEnd('\\') + "\\" + tail, scanNt)) return No(OnScannedDrive);
        }
        return new(true, null);
    }

    /// <summary>
    /// Walks the existing part of <paramref name="full"/> (a drive path) from the root WITHOUT following links. Any
    /// reparse point (junction, symlink, mount point, cloud placeholder) is a problem. <paramref name="deepest"/> is the
    /// deepest folder that exists (null if not even the root can be opened).
    /// </summary>
    internal static string? ChainProblem(string full, ILocationProbe probe, out string? deepest)
    {
        deepest = null;
        var root = full[..3];
        var rootEntry = probe.Entry(root);
        if (rootEntry is null) return null;
        if (rootEntry.Value.IsCloud) return $"Drive {full[..2]} is cloud-synced. {PickLocal}";
        deepest = root;
        var current = root;
        foreach (var part in full[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Join(current, part);
            var entry = probe.Entry(current);
            if (entry is null) break;                       // the rest does not exist yet
            if (entry.Value.IsCloud) return $"This folder is cloud-synced ({current}). {PickLocal}";
            if (entry.Value.IsReparsePoint) return $"{current} is a link to another location. Pick a normal folder.";
            deepest = current;
        }
        return null;
    }

    /// <summary>Name-based checks: OneDrive environment roots and well-known sync-folder names.</summary>
    static string? Lexical(string full, Func<string, string?> getEnv)
    {
        foreach (var name in EnvRoots)
            if (getEnv(name) is { Length: > 0 } root && IsUnder(full, root))
                return $"This folder is synced by OneDrive ({root}). {PickLocal}";

        foreach (var part in full.Split('\\'))
        {
            // Environment variables belong to whoever elevated, so also catch OneDrive folders by name.
            if (part.Equals("OneDrive", StringComparison.OrdinalIgnoreCase) || part.StartsWith("OneDrive - ", StringComparison.OrdinalIgnoreCase))
                return $"This folder looks synced by OneDrive ({part}). {PickLocal}";
            foreach (var synced in SyncedFolderNames)
                if (part.Equals(synced, StringComparison.OrdinalIgnoreCase)
                    || part.StartsWith(synced + " (", StringComparison.OrdinalIgnoreCase))
                    return $"This folder looks cloud-synced ({part}). {PickLocal}";
        }
        return null;
    }

    static bool IsDrivePath(string p) => p.Length >= 2 && char.IsAsciiLetter(p[0]) && p[1] == ':' && (p.Length == 2 || p[2] == '\\');

    static bool IsNetworkDevice(string target) =>
        target.StartsWith(@"\Device\LanmanRedirector", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith(@"\Device\Mup", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith(@"\Device\WebDavRedirector", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith(@"\Device\RdpDr", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase);

    static bool IsUnder(string path, string root)
    {
        root = root.TrimEnd('\\');
        if (root.Length == 0) return false;
        return path.TrimEnd('\\').Equals(root, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
    }

    static CaseLocationResult No(string reason) => new(false, reason);
}

/// <summary>What the save-folder checks ask the system (a fake in tests).</summary>
internal interface ILocationProbe
{
    DriveType DriveType(string root);
    string? DosDeviceTarget(string driveLetter);
    (string? Label, string? FileSystem) Volume(string root);
    EntryInfo? Entry(string path);
    string? FinalPath(string path);
    string? NtPath(string path);
    IEnumerable<string> SyncRoots();
    bool? IsReadOnlyVolume(string root);
}

internal sealed class WindowsProbe : ILocationProbe
{
    public static readonly WindowsProbe Instance = new();

    public DriveType DriveType(string root)
    {
        try { return new DriveInfo(root).DriveType; }
        catch (Exception e) when (e is ArgumentException or IOException) { return System.IO.DriveType.NoRootDirectory; }
    }

    public string? DosDeviceTarget(string driveLetter) => FileIdentity.DosDeviceTarget(driveLetter);
    public (string? Label, string? FileSystem) Volume(string root) => FileIdentity.VolumeInfo(root);
    public EntryInfo? Entry(string path) => FileIdentity.Entry(path);
    public string? FinalPath(string path) => FileIdentity.FinalPath(path);
    public string? NtPath(string path) => FileIdentity.NtPath(path);
    public bool? IsReadOnlyVolume(string root) => FileIdentity.IsReadOnlyVolume(root);

    /// <summary>
    /// Every cloud sync root Windows knows: SyncRootManager (all accounts: OneDrive, SharePoint, Dropbox, iCloud, Box,
    /// Google Drive ...) plus OneDrive's own account folders and SharePoint/Teams library mount points for every loaded
    /// user hive (relocated OneDrive folders included).
    /// </summary>
    public IEnumerable<string> SyncRoots()
    {
        var roots = new List<string>();
        Try(() =>
        {
            using var mgr = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager");
            foreach (var name in mgr?.GetSubKeyNames() ?? [])
                Try(() =>
                {
                    using var users = mgr!.OpenSubKey(name + @"\UserSyncRoots");
                    foreach (var v in users?.GetValueNames() ?? []) if (users!.GetValue(v) is string s) roots.Add(s);
                });
        });
        Try(() =>
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
                Try(() =>
                {
                    using var accounts = Registry.Users.OpenSubKey(sid + @"\Software\Microsoft\OneDrive\Accounts");
                    foreach (var account in accounts?.GetSubKeyNames() ?? [])
                        Try(() =>
                        {
                            using var a = accounts!.OpenSubKey(account);
                            if (a?.GetValue("UserFolder") is string folder) roots.Add(folder);
                            using var mounts = a?.OpenSubKey("ScopeIdToMountPointPathCache");
                            foreach (var v in mounts?.GetValueNames() ?? []) if (mounts!.GetValue(v) is string s) roots.Add(s);
                        });
                });
        });
        return roots.Where(r => r.Length >= 3).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    static void Try(Action a)
    {
        try { a(); }
        catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException) { }
    }
}
