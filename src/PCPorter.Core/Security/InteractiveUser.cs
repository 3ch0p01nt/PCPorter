using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace PCPorter.Core.Security;

/// <summary>A Windows account: its SID, its name (DOMAIN\user) and its profile folder (null when unknown).</summary>
public sealed record Account(SecurityIdentifier Sid, string Name, string? ProfilePath)
{
    /// <summary>The user part of <see cref="Name"/>: "bob" for "PC\bob".</summary>
    public string ShortName => Name[(Name.LastIndexOf('\\') + 1)..];
}

/// <summary>
/// Who PCPorter works for. On a family PC a standard user may type an administrator's password at the UAC prompt:
/// PCPorter then runs as that administrator (<see cref="Process"/>), but the person at the PC is still the account signed
/// in to Windows (<see cref="SignedIn"/>). "This account" (profile folder, history, thumbnails, Store apps) means the
/// signed-in account; the case folder is private to both.
/// </summary>
public sealed record Accounts(Account Process, Account SignedIn)
{
    public bool Differ => Process.Sid != SignedIn.Sid;

    /// <summary>The line every page shows when the two differ; null when they are the same account.</summary>
    public string? Note => Differ
        ? $"Checking the account of {SignedIn.ShortName} (PCPorter was started with {Process.ShortName}'s password)."
        : null;

    /// <summary>The accounts a new case folder is private to (besides SYSTEM and Administrators): the signed-in one and, when different, the running one.</summary>
    public IReadOnlyList<SecurityIdentifier> CaseOwners => Differ ? [SignedIn.Sid, Process.Sid] : [SignedIn.Sid];
}

/// <summary>Finds the account signed in to this Windows session (see <see cref="Accounts"/>).</summary>
public static class InteractiveUser
{
    static readonly Lazy<Accounts> _current = new(Find);

    /// <summary>This process's accounts, found once (they cannot change while it runs).</summary>
    public static Accounts Current => _current.Value;

    /// <summary>
    /// The decision: the session's user when it is known and has a profile folder, else the process's own account
    /// (so PCPorter never works for an account whose files it cannot find).
    /// </summary>
    public static Accounts Decide(Account process, Account? sessionUser) =>
        sessionUser is { ProfilePath: not null } s && s.Sid != process.Sid
            ? new Accounts(process, s)
            : new Accounts(process, process);

    static Accounts Find()
    {
        using var id = WindowsIdentity.GetCurrent();
        var sid = id.User!;
        var process = new Account(sid, id.Name, ProfileOf(sid) ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        return Decide(process, SessionUser());
    }

    /// <summary>
    /// The user of this process's Windows session (WTSQuerySessionInformation: works for any account, no special rights),
    /// resolved to a SID; null when the session has no user or the name cannot be resolved.
    /// </summary>
    static Account? SessionUser()
    {
        try
        {
            int session = Process.GetCurrentProcess().SessionId;
            var user = Query(session, WtsUserName);
            var domain = Query(session, WtsDomainName);
            if (string.IsNullOrEmpty(user)) return null;
            var name = string.IsNullOrEmpty(domain) ? user : domain + "\\" + user;
            var sid = (SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier));
            return new Account(sid, name, ProfileOf(sid));
        }
        // Translate throws a plain SystemException for a lookup failure; IdentityNotMappedException derives from it.
        catch (SystemException e) when (e is not (OutOfMemoryException or StackOverflowException)) { return null; }
    }

    /// <summary>The profile folder Windows records for <paramref name="sid"/> (ProfileList), or null.</summary>
    public static string? ProfileOf(SecurityIdentifier sid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid.Value);
            return key?.GetValue("ProfileImagePath") is string path && path.Length > 0 ? Environment.ExpandEnvironmentVariables(path) : null;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    static string? Query(int session, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out var buffer, out _)) return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    const int WtsUserName = 5, WtsDomainName = 7;

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern void WTSFreeMemory(IntPtr memory);
}
