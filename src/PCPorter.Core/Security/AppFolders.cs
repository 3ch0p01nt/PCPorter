using System.Security.AccessControl;
using System.Security.Principal;

namespace PCPorter.Core.Security;

/// <summary>
/// Where PCPorter keeps its own working files (logs, the shadow-copy journal).
/// Elevated: %ProgramData%\PCPorter\&lt;name&gt;, writable only by SYSTEM and Administrators, so a normal user (or malware
/// running as that user) cannot plant a junction or edit the journal an admin process later acts on.
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

    public static string For(string name) => For(name, IsElevated);

    public static string For(string name, bool elevated)
    {
        if (elevated)
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PCPorter");
            try
            {
                EnsureAdminOnly(root);
                var sub = Path.Combine(root, name);
                EnsureAdminOnly(sub);
                return sub;
            }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException) { }
        }
        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCPorter", name);
        Directory.CreateDirectory(local);
        return local;
    }

    /// <summary>Creates the folder (or re-locks an existing one) with only SYSTEM + Administrators, owned by Administrators.</summary>
    static void EnsureAdminOnly(string path)
    {
        var info = new DirectoryInfo(path);
        if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException($"{path} is a link; refusing to use it.");
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), admins })
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (!info.Exists) { info.Create(sec); info.Refresh(); }
        sec.SetOwner(admins);
        info.SetAccessControl(sec);   // a folder a normal user pre-created is re-locked (or this throws and we fall back)
    }
}
