using System.Security.AccessControl;
using System.Security.Principal;

namespace PCPorter.Core.Security;

/// <summary>
/// PCPorter's admin-only working folder could not be made safe (for example another account created it as a link,
/// or its permissions could not be locked). The message is written for the person and is safe to show.
/// </summary>
public sealed class UnsafeAppFolderException(string message, Exception? inner = null) : IOException(message, inner);

/// <summary>
/// Where PCPorter keeps its own working files (logs, the shadow-copy journal).
/// Elevated: %ProgramData%\PCPorter\&lt;name&gt;, owned by Administrators and writable only by SYSTEM and Administrators,
/// so a normal user (or malware running as that user) cannot plant a junction or edit the journal an admin process later
/// acts on. If that cannot be guaranteed, an elevated run fails (<see cref="UnsafeAppFolderException"/>) instead of
/// falling back to a folder the user can write.
/// Not elevated: %LocalAppData%\PCPorter\&lt;name&gt;, as before.
/// </summary>
public static class AppFolders
{
    public static bool IsElevated
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <exception cref="UnsafeAppFolderException">Elevated, and the admin-only folder could not be made safe.</exception>
    public static string For(string name) => For(name, IsElevated);

    /// <exception cref="UnsafeAppFolderException">Elevated, and the admin-only folder could not be made safe.</exception>
    public static string For(string name, bool elevated) =>
        For(name, elevated, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    internal static string For(string name, bool elevated, string programData)
    {
        if (elevated)
        {
            var root = Path.Combine(programData, "PCPorter");
            try
            {
                EnsureAdminOnly(root);
                var sub = Path.Combine(root, name);
                EnsureAdminOnly(sub);
                return sub;
            }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException or PrivilegeNotHeldException)
            {
                throw new UnsafeAppFolderException(
                    $"PCPorter could not make its working folder {root} safe ({e.Message}) It may have been created by another account. " +
                    "Remove that folder as administrator and try again.", e);
            }
        }
        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCPorter", name);
        Directory.CreateDirectory(local);
        return local;
    }

    static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>SYSTEM or Administrators: the only owners an elevated PCPorter trusts for its own files.</summary>
    public static bool IsAdminSid(IdentityReference? sid) => sid is SecurityIdentifier s && (s == Admins || s == SystemSid);

    /// <summary>True when only SYSTEM and Administrators may change the object (owner and every allow rule that grants writing).</summary>
    public static bool IsAdminOnly(FileSystemSecurity sec)
    {
        if (!IsAdminSid(sec.GetOwner(typeof(SecurityIdentifier)))) return false;
        const FileSystemRights write = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteAttributes |
                                       FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                                       FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0 && !IsAdminSid(rule.IdentityReference))
                return false;
        return true;
    }

    /// <summary>Creates the folder (or re-locks an existing one) with only SYSTEM + Administrators, owned by Administrators, then verifies it.</summary>
    static void EnsureAdminOnly(string path)
    {
        var info = new DirectoryInfo(path);
        if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException($"{path} is a link; refusing to use it.");
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { SystemSid, Admins })
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (!info.Exists) { info.Create(sec); info.Refresh(); }
        sec.SetOwner(Admins);
        info.SetAccessControl(sec);   // a folder a normal user pre-created is re-locked (or this throws)

        info.Refresh();
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || !IsAdminOnly(info.GetAccessControl()))
            throw new InvalidOperationException($"{path} could not be locked to administrators.");
    }
}
