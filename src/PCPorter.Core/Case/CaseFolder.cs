using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using PCPorter.Core.Security;

namespace PCPorter.Core.Case;

public sealed class CaseLocationRejectedException(string message) : Exception(message);

public sealed record CaseFolderInfo(string Path, IReadOnlyList<string> Warnings);

/// <summary>The file system of a volume: its name for messages, and whether it keeps per-file permissions (NTFS, ReFS).</summary>
public sealed record VolumeFormat(string Name, bool KeepsPermissions);

/// <summary>
/// Creates a new, private case folder: unique name, protected ACL (SYSTEM, Administrators and the person running
/// PCPorter only), excluded from Windows Search indexing, and never through a junction or symlink. On a drive that
/// cannot keep permissions (exFAT, FAT32) the folders are made without an ACL and a warning says anyone can read them.
/// </summary>
public static class CaseFolder
{
    public static CaseFolderInfo Create(string outRoot, DateTimeOffset now, string? computerName = null, Func<string, string?>? getEnv = null) =>
        Create(outRoot, now, computerName, getEnv, FormatOf);

    internal static CaseFolderInfo Create(string outRoot, DateTimeOffset now, string? computerName, Func<string, string?>? getEnv,
        Func<string, VolumeFormat?> formatOf)
    {
        var check = CaseLocation.Check(outRoot, getEnv);
        if (!check.IsAllowed) throw new CaseLocationRejectedException(check.Reason!);

        var warnings = new List<string>();
        var full = Path.GetFullPath(outRoot);
        RejectLinks(full);                  // the existing folders on the way, BEFORE anything is created through them
        Directory.CreateDirectory(full);
        RejectLinks(full);                  // and again, in case one was swapped in meanwhile

        var format = formatOf(full);
        if (format is { KeepsPermissions: false })
            warnings.Add($"This drive uses {format.Name}, which cannot restrict who can read the files. Anyone with the drive can open the case. Consider BitLocker To Go.");

        var root = Path.Combine(full, "PCPorter");
        if (Directory.Exists(root)) RejectLinks(root);
        else CreatePrivate(root, formatOf);

        var name = $"{Safe(computerName ?? Environment.MachineName)}_{now.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}_{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";
        var path = Path.Combine(root, name);
        if (Directory.Exists(path) || File.Exists(path))
            throw new CaseLocationRejectedException($"A case folder named {name} already exists.");
        CreatePrivate(path, formatOf);
        new DirectoryInfo(path).Attributes |= FileAttributes.NotContentIndexed;

        return new CaseFolderInfo(path, warnings);
    }

    /// <summary>Folder whose ACL allows only SYSTEM, Administrators and the current user; inherited by everything inside.
    /// On a drive without permissions (exFAT, FAT32) it is a plain folder: setting an ACL there fails.</summary>
    public static void CreatePrivate(string path) => CreatePrivate(path, FormatOf);

    internal static void CreatePrivate(string path, Func<string, VolumeFormat?> formatOf)
    {
        if (formatOf(path) is { KeepsPermissions: false }) { Directory.CreateDirectory(path); return; }
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in PrivateSids())
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(sec);
        // Create() leaves an existing folder's ACL alone; set it explicitly so the rule always holds.
        new DirectoryInfo(path).SetAccessControl(sec);
    }

    /// <summary>
    /// Where a run keeps its temporary copies (browser history files, the search index, Windows.edb): a private folder
    /// per case under PCPorter's own working folder on the system drive (admin-only when elevated, see
    /// <see cref="AppFolders"/>), never on the save drive, which may be FAT32 (4 GB per file) or readable by anyone.
    /// </summary>
    public static string WorkFolderFor(string casePath) => Path.Combine(AppFolders.For("work"), Path.GetFileName(Path.TrimEndingDirectorySeparator(casePath)));

    /// <summary>Creates <see cref="WorkFolderFor"/>(<paramref name="casePath"/>), private to this run. The caller deletes it at the end.</summary>
    public static string CreateWork(string casePath)
    {
        var work = WorkFolderFor(casePath);
        var info = new DirectoryInfo(work);
        if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new IOException($"{work} is a link; refusing to use it.");
        CreatePrivate(work);
        return work;
    }

    public static IEnumerable<SecurityIdentifier> PrivateSids()
    {
        yield return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        yield return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        if (WindowsIdentity.GetCurrent().User is { } me) yield return me;
    }

    /// <summary>The file system of the volume holding <paramref name="path"/>, or null when it cannot be read.</summary>
    public static VolumeFormat? FormatOf(string path)
    {
        try
        {
            var name = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(path))!).DriveFormat;
            return new VolumeFormat(name, name.Equals("NTFS", StringComparison.OrdinalIgnoreCase) || name.Equals("ReFS", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception e) when (e is IOException or ArgumentException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Any reparse point among the existing folders of <paramref name="path"/> (checked from the root down, links not followed) is refused.</summary>
    static void RejectLinks(string path)
    {
        var drive = path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
        if (drive.Length < 3 || drive[1] != ':') throw new CaseLocationRejectedException(@"Pick a full folder path, for example E:\PCPorter.");
        if (CaseLocation.ChainProblem(Path.TrimEndingDirectorySeparator(drive), WindowsProbe.Instance, out _) is { } problem)
            throw new CaseLocationRejectedException(problem);
    }

    static string Safe(string s) => string.Concat(s.Select(c => char.IsLetterOrDigit(c) || c is '-' ? c : '_'));
}
