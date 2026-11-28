using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Offline;

public enum OfflineVolumeState { WindowsFound, Locked }

/// <summary>A drive that may hold another PC's Windows.</summary>
/// <param name="Root">"D:\" (null for a locked volume without a drive letter).</param>
/// <param name="DeviceId">BitLocker volume id (Win32_EncryptableVolume.DeviceID) when known; used to unlock.</param>
public sealed record OfflineVolume(string? Root, string? DeviceId, OfflineVolumeState State, string? OsName, string? Build, string Description);

public sealed record OfflineVolumeScan(IReadOnlyList<OfflineVolume> Volumes, IReadOnlyList<string> Notes);

/// <summary>
/// Finds attached drives with a Windows installation (dead-PC mode), plus BitLocker-locked volumes that cannot be
/// read yet. The running Windows volume is always skipped. Read-only.
/// </summary>
public sealed class OfflineVolumeFinder
{
    public const string BitLockerNamespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";
    public const string LockedDescription = "locked - needs recovery key";

    readonly IWmiClient _wmi;
    readonly Func<IEnumerable<string>> _drives;
    readonly Func<string, bool>? _fileExists;
    readonly string _runningWindowsDrive;
    readonly Func<string, (string? OsName, string? Build)> _readOs;

    /// <param name="drives">Drive roots like "D:\"; defaults to this PC's ready fixed/removable drives.</param>
    /// <param name="fileExists">Defaults to a check confined to the drive that never follows a link (see <see cref="SourcePresence"/>).</param>
    /// <param name="runningWindowsDrive">Defaults to the drive of the running Windows.</param>
    /// <param name="readOs">Reads OS name/build from a root; defaults to <see cref="ReadOs"/> via <see cref="OfflineSource"/>.</param>
    public OfflineVolumeFinder(IWmiClient wmi, Func<IEnumerable<string>>? drives = null, Func<string, bool>? fileExists = null,
        string? runningWindowsDrive = null, Func<string, (string? OsName, string? Build)>? readOs = null)
    {
        _wmi = wmi;
        _drives = drives ?? DefaultDrives;
        _fileExists = fileExists;
        _runningWindowsDrive = NormalizeRoot(runningWindowsDrive ?? Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\")!;
        _readOs = readOs ?? ReadOs;
    }

    public OfflineVolumeScan Find()
    {
        var notes = new List<string>();
        var found = new List<OfflineVolume>();
        var seenRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in _drives())
        {
            var root = NormalizeRoot(raw);
            if (root is null || IsRunning(root) || !seenRoots.Add(root)) continue;
            var software = Path.Combine(root, "Windows", "System32", "config", "SOFTWARE");
            if (!(_fileExists?.Invoke(software) ?? ExistsOnDrive(root, software))) continue;
            try
            {
                var (os, build) = _readOs(root);
                found.Add(new OfflineVolume(root, null, OfflineVolumeState.WindowsFound, os, build, Describe(os, build)));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException)
            {
                found.Add(new OfflineVolume(root, null, OfflineVolumeState.WindowsFound, null, null, "Windows found, but its settings could not be read."));
                notes.Add($"{root}: {e.Message}");
            }
        }

        var bitlocker = _wmi.Query(BitLockerNamespace, "SELECT DeviceID, DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume");
        switch (bitlocker.Outcome)
        {
            case WmiOutcome.Ok:
                foreach (var row in bitlocker.Rows)
                {
                    if (!IsLocked(row)) continue;
                    var letter = row.TryGetValue("DriveLetter", out var dl) ? dl as string : null;
                    var root = string.IsNullOrWhiteSpace(letter) ? null : NormalizeRoot(letter);
                    if (root is not null && (IsRunning(root) || seenRoots.Contains(root))) continue;
                    var deviceId = row.TryGetValue("DeviceID", out var id) ? id as string : null;
                    found.Add(new OfflineVolume(root, deviceId, OfflineVolumeState.Locked, null, null, LockedDescription));
                }
                break;
            case WmiOutcome.AccessDenied:
                notes.Add("BitLocker-locked drives are only listed when PCPorter runs as administrator.");
                break;
            case WmiOutcome.InvalidNamespace:
                break;   // no BitLocker on this edition
            default:
                notes.Add($"BitLocker drives could not be listed ({bitlocker.Outcome}).");
                break;
        }
        return new OfflineVolumeScan(found, notes);
    }

    /// <summary>
    /// ProtectionStatus 2 ("unknown") is what Win32_EncryptableVolume reports for a locked volume; a volume that is
    /// encrypted (ConversionStatus != 0) and still reports no protection state is treated the same way.
    /// </summary>
    public static bool IsLocked(IReadOnlyDictionary<string, object?> row)
    {
        var protection = AsLong(row.TryGetValue("ProtectionStatus", out var p) ? p : null);
        var conversion = AsLong(row.TryGetValue("ConversionStatus", out var c) ? c : null);
        if (protection == 2) return true;
        return protection is null && conversion is > 0;
    }

    static long? AsLong(object? v) => v switch
    {
        null => null,
        uint u => u,
        int i => i,
        long l => l,
        ulong ul => (long)ul,
        ushort us => us,
        byte b => b,
        string s when long.TryParse(s, out var x) => x,
        _ => null,
    };

    /// <summary>
    /// The drive picker looks at every attached drive before anything is chosen: a "Windows" folder that is really a
    /// link (possibly to a network share) on a USB stick must not be followed just by listing drives.
    /// </summary>
    static bool ExistsOnDrive(string root, string path)
    {
        using var confine = Sources.SourceFiles.Confine(root);
        return SourcePresence.IsFile(path);
    }

    bool IsRunning(string root) => string.Equals(root, _runningWindowsDrive, StringComparison.OrdinalIgnoreCase);

    static string Describe(string? os, string? build) =>
        os is null ? "Windows found" : build is null ? os : $"{os} (build {build})";

    /// <summary>"D", "D:", "d:\" => "D:\"; other fully qualified folders get a trailing backslash; anything else is null.</summary>
    public static string? NormalizeRoot(string? drive)
    {
        if (string.IsNullOrWhiteSpace(drive)) return null;
        var d = drive.Trim();
        if (!char.IsAsciiLetter(d[0])) return null;
        if (d.Length == 1 || (d.Length == 2 && d[1] == ':') || (d.Length == 3 && d[1] == ':' && d[2] == '\\'))
            return char.ToUpperInvariant(d[0]) + @":\";
        if (Path.IsPathFullyQualified(d)) return d.EndsWith('\\') ? d : d + "\\";   // mounted folder or test root
        return null;
    }

    static IEnumerable<string> DefaultDrives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ready;
            try { ready = d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable; }
            catch (IOException) { ready = false; }
            if (ready) yield return d.RootDirectory.FullName;
        }
    }

    /// <summary>OS name and build from the drive's SOFTWARE hive (parsed in memory).</summary>
    public static (string? OsName, string? Build) ReadOs(string root)
    {
        using var source = new OfflineSource(root);
        var cv = source.OpenHive(Hive.Software)?.Open(@"Microsoft\Windows NT\CurrentVersion");
        if (cv is null) return (null, null);
        var build = cv.GetString("CurrentBuild") ?? cv.GetString("CurrentBuildNumber");
        return (OsName(cv.GetString("ProductName"), build), build);
    }

    /// <summary>Windows 11 still says "Windows 10" in ProductName; build >= 22000 is Windows 11.</summary>
    public static string? OsName(string? productName, string? build)
    {
        if (productName is null) return null;
        if (int.TryParse(build, out var b) && b >= 22000 && productName.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
            return "Windows 11" + productName["Windows 10".Length..];
        return productName;
    }
}
