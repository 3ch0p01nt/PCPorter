using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace PCPorter.Core.Case;

public sealed class CaseLocationRejectedException(string message) : Exception(message);

public sealed record CaseFolderInfo(string Path, IReadOnlyList<string> Warnings);

/// <summary>
/// Creates a new, private case folder: unique name, protected ACL (SYSTEM, Administrators and the person running
/// PCPorter only), excluded from Windows Search indexing, and never through a junction or symlink.
/// </summary>
public static class CaseFolder
{
    public static CaseFolderInfo Create(string outRoot, DateTimeOffset now, string? computerName = null, Func<string, string?>? getEnv = null)
    {
        var check = CaseLocation.Check(outRoot, getEnv);
        if (!check.IsAllowed) throw new CaseLocationRejectedException(check.Reason!);

        var warnings = new List<string>();
        var full = Path.GetFullPath(outRoot);
        RejectLinks(full);                  // the existing folders on the way, BEFORE anything is created through them
        Directory.CreateDirectory(full);
        RejectLinks(full);                  // and again, in case one was swapped in meanwhile

        var root = Path.Combine(full, "PCPorter");
        if (Directory.Exists(root)) RejectLinks(root);
        else CreatePrivate(root);

        var name = $"{Safe(computerName ?? Environment.MachineName)}_{now.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}_{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";
        var path = Path.Combine(root, name);
        if (Directory.Exists(path) || File.Exists(path))
            throw new CaseLocationRejectedException($"A case folder named {name} already exists.");
        CreatePrivate(path);
        new DirectoryInfo(path).Attributes |= FileAttributes.NotContentIndexed;

        try
        {
            var format = new DriveInfo(Path.GetPathRoot(full)!).DriveFormat;
            if (!format.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
                warnings.Add($"This drive uses {format}, which cannot restrict who can read the files. Anyone with the drive can open the case. Consider BitLocker To Go.");
        }
        catch (Exception e) when (e is IOException or ArgumentException or UnauthorizedAccessException) { }

        return new CaseFolderInfo(path, warnings);
    }

    /// <summary>Folder whose ACL allows only SYSTEM, Administrators and the current user; inherited by everything inside.</summary>
    public static void CreatePrivate(string path)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in PrivateSids())
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(sec);
        // Create() leaves an existing folder's ACL alone; set it explicitly so the rule always holds.
        new DirectoryInfo(path).SetAccessControl(sec);
    }

    public static IEnumerable<SecurityIdentifier> PrivateSids()
    {
        yield return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        yield return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        if (WindowsIdentity.GetCurrent().User is { } me) yield return me;
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
