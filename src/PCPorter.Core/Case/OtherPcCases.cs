using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using PCPorter.Core.IO;

namespace PCPorter.Core.Case;

/// <summary>A case folder found on a drive: which PC made it, when, and which reports it holds.</summary>
/// <param name="Reports">The reports in it, by name ("Health and security", "Web history", "Images viewed"); empty when
/// the folder could not be read yet (another account's results, before <see cref="OtherPcCases.GrantRead"/>).</param>
public sealed record FoundCase(string Path, string ComputerName, DateTimeOffset CreatedUtc, IReadOnlyList<string> Reports, bool Readable)
{
    public override string ToString()
    {
        var reports = Reports.Count > 0 ? string.Join(", ", Reports) : Readable ? "no report" : "locked to the old PC's account";
        return $"{ComputerName}, {CreatedUtc.ToLocalTime():d MMM yyyy HH:mm} - {reports} ({System.IO.Path.GetPathRoot(Path)?.TrimEnd('\\')})";
    }
}

/// <summary>What a search found: the case folders, and the PCPorter folders that could not be listed (not administrator).</summary>
public sealed record CaseSearch(IReadOnlyList<FoundCase> Cases, IReadOnlyList<string> Unreadable);

/// <summary>
/// "Open results from another PC". Case folders are private to the account that made them (SYSTEM, Administrators and
/// that person's SID), so on the new PC the person's own browser and File Explorer get "access denied". This finds the
/// case folders on the connected drives and, after the person agrees, gives the current account read access to one of
/// them. It only ever touches a folder that is really a PCPorter case folder: the name PCPorter gives, inside a folder
/// named PCPorter, with its case.db, on a local drive, and with no link (junction, symlink, mount point, hard link)
/// anywhere on the way or inside.
/// </summary>
public static partial class OtherPcCases
{
    [GeneratedRegex(@"^(?<pc>[\p{L}\p{Nd}_-]+)_(?<when>\d{8}T\d{6}Z)_[0-9a-f]{6}$", RegexOptions.CultureInvariant)]
    private static partial Regex CaseName();

    /// <summary>The reports a case folder can hold (path inside the case, name shown to the person).</summary>
    public static readonly IReadOnlyList<(string File, string Name)> KnownReports =
        [("HealthReport.html", "Health and security"), ("History.html", "Web history"), (System.IO.Path.Combine("Thumbnails", "Thumbnails.html"), "Images viewed")];

    /// <summary>
    /// Case folders in <c>&lt;drive&gt;\PCPorter</c> on every ready local drive, newest first. Slow for a sleeping USB
    /// disk: call off the UI thread.
    /// </summary>
    public static CaseSearch FindOnDrives()
    {
        var roots = new List<string>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
                try { if (d.DriveType is DriveType.Fixed or DriveType.Removable && d.IsReady) roots.Add(d.RootDirectory.FullName); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return Merge(roots.Select(FindIn));
    }

    /// <summary>
    /// Case folders in <paramref name="folder"/>: the folder itself if it is one, the cases inside it if it is a
    /// PCPorter folder, else the cases in its PCPorter subfolder (where PCPorter saves them). Newest first.
    /// </summary>
    public static CaseSearch FindIn(string folder)
    {
        var cases = new List<FoundCase>();
        var unreadable = new List<string>();
        string full;
        try { full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return new([], []); }
        if (full.Length == 2) full += "\\";

        if (Describe(full) is { } self) cases.Add(self);
        else
        {
            var root = string.Equals(Path.GetFileName(full), "PCPorter", StringComparison.OrdinalIgnoreCase) ? full : Path.Combine(full, "PCPorter");
            if (IsPlainFolder(root))
            {
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root))
                        if (Describe(dir) is { } found) cases.Add(found);
                }
                catch (UnauthorizedAccessException) { unreadable.Add(root); }
                catch (IOException) { }
            }
        }
        return new(cases.OrderByDescending(c => c.CreatedUtc).ToList(), unreadable);
    }

    static CaseSearch Merge(IEnumerable<CaseSearch> parts)
    {
        var list = parts.ToList();
        return new(list.SelectMany(p => p.Cases).OrderByDescending(c => c.CreatedUtc).ToList(), list.SelectMany(p => p.Unreadable).ToList());
    }

    /// <summary>The case at <paramref name="path"/>, or null when it is not a PCPorter case folder (by name, place, links and case.db).</summary>
    static FoundCase? Describe(string path)
    {
        if (!LooksLikeCase(path, out var pc, out var when) || !IsPlainFolder(path)) return null;
        bool readable = true;
        try { using var entries = Directory.EnumerateFileSystemEntries(path).GetEnumerator(); entries.MoveNext(); }
        catch (UnauthorizedAccessException) { readable = false; }
        catch (IOException) { return null; }
        if (readable && !HasCaseDb(path)) return null;            // readable and no case.db: not a case
        var reports = readable ? KnownReports.Where(r => File.Exists(Path.Combine(path, r.File))).Select(r => r.Name).ToList() : [];
        return new FoundCase(path, pc, when, reports, readable);
    }

    /// <summary>The name and place PCPorter gives a case folder: <c>...\PCPorter\&lt;PC&gt;_&lt;yyyyMMddTHHmmssZ&gt;_&lt;6 hex&gt;</c>.</summary>
    public static bool LooksLikeCase(string path, out string computerName, out DateTimeOffset createdUtc)
    {
        computerName = ""; createdUtc = default;
        var trimmed = Path.TrimEndingDirectorySeparator(path);
        var parent = Path.GetDirectoryName(trimmed);
        var m = CaseName().Match(Path.GetFileName(trimmed));
        if (!m.Success || parent is null || !string.Equals(Path.GetFileName(parent), "PCPorter", StringComparison.OrdinalIgnoreCase)) return false;
        if (!DateTime.TryParseExact(m.Groups["when"].Value, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)) return false;
        computerName = m.Groups["pc"].Value;
        createdUtc = new DateTimeOffset(t, TimeSpan.Zero);
        return true;
    }

    /// <summary>
    /// Gives <paramref name="sid"/> read access (read and execute, inherited by everything inside) to the case folder at
    /// <paramref name="casePath"/>, keeping every existing rule. Needs administrator rights for another account's case.
    /// </summary>
    /// <exception cref="CaseLocationRejectedException">Not a PCPorter case folder, or a link was found; nothing was changed.</exception>
    public static void GrantRead(string casePath, SecurityIdentifier sid)
    {
        var full = CheckCase(casePath);
        // The case folder, then every folder or file inside whose permissions do not inherit (PCPorter makes its
        // subfolders private too): each gets the rule, and Windows passes it on to everything that does inherit.
        foreach (var path in Protected(full).ToList())           // the whole walk first: a read error changes nothing
        {
            var isDir = Directory.Exists(path);
            FileSystemSecurity sec = isDir ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
                                           : new FileInfo(path).GetAccessControl(AccessControlSections.Access);
            sec.AddAccessRule(isDir
                ? new FileSystemAccessRule(sid, ReadRights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)
                : new FileSystemAccessRule(sid, ReadRights, AccessControlType.Allow));
            SetProtectedDacl(path, sec);
        }
    }

    const FileSystemRights ReadRights = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;

    /// <summary>
    /// True when the case folder's own rules already let <paramref name="sid"/> itself read it (the account that made it,
    /// or one given read before). Group rules do not count: Administrators only helps an elevated program, not the
    /// browser or File Explorer.
    /// </summary>
    public static bool CanRead(string casePath, SecurityIdentifier sid) => CanRead(casePath, sid, CaseFolder.FormatOf);

    /// <remarks>On a drive that keeps no permissions (exFAT, FAT32) everyone can read it: there is nothing to grant.</remarks>
    internal static bool CanRead(string casePath, SecurityIdentifier sid, Func<string, VolumeFormat?> formatOf)
    {
        if (Directory.Exists(casePath) && formatOf(casePath) is { KeepsPermissions: false }) return true;
        try
        {
            var rules = new DirectoryInfo(casePath).GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Where(r => sid.Equals(r.IdentityReference)).ToList();
            return rules.Any(r => r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute)
                   && !rules.Any(r => r.AccessControlType == AccessControlType.Deny);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException) { return false; }
    }

    /// <summary><paramref name="root"/> and every entry below it with a protected ACL, parents first (links were refused already).</summary>
    static IEnumerable<string> Protected(string root)
    {
        yield return root;
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            foreach (var entry in new DirectoryInfo(pending.Pop()).EnumerateFileSystemInfos())
            {
                var isDir = entry.Attributes.HasFlag(FileAttributes.Directory);
                FileSystemSecurity sec = isDir ? ((DirectoryInfo)entry).GetAccessControl(AccessControlSections.Access) : ((FileInfo)entry).GetAccessControl(AccessControlSections.Access);
                if (sec.AreAccessRulesProtected) yield return entry.FullName;
                if (isDir) pending.Push(entry.FullName);
            }
        }
    }

    /// <summary>
    /// Writes the DACL with SetNamedSecurityInfo, which (unlike .NET's SetAccessControl) passes inheritable rules on to
    /// the folders and files already inside. The ACL stays protected: nothing above is inherited.
    /// </summary>
    static void SetProtectedDacl(string path, FileSystemSecurity sec)
    {
        var raw = new RawSecurityDescriptor(sec.GetSecurityDescriptorBinaryForm(), 0);
        var dacl = new byte[raw.DiscretionaryAcl!.BinaryLength];
        raw.DiscretionaryAcl.GetBinaryForm(dacl, 0);
        const uint DaclSecurityInformation = 0x4, ProtectedDacl = 0x80000000;
        var error = SetNamedSecurityInfo(path, 1 /* SE_FILE_OBJECT */, DaclSecurityInformation | ProtectedDacl, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
        if (error != 0) throw new System.ComponentModel.Win32Exception((int)error);
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
    [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
    static extern uint SetNamedSecurityInfo(string name, int objectType, uint securityInfo, IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);

    /// <summary>The checked full path of a case folder that may be changed, or a <see cref="CaseLocationRejectedException"/>.</summary>
    internal static string CheckCase(string casePath)
    {
        const string NotACase = "This is not a PCPorter results folder, so PCPorter will not change it.";
        if (string.IsNullOrWhiteSpace(casePath) || !Path.IsPathFullyQualified(casePath)) throw new CaseLocationRejectedException(NotACase);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(casePath));
        if (full.Length < 4 || !char.IsAsciiLetter(full[0]) || full[1] != ':' || full[2] != '\\'
            || !string.Equals(full, Path.TrimEndingDirectorySeparator(casePath), StringComparison.OrdinalIgnoreCase))
            throw new CaseLocationRejectedException(NotACase);
        if (!LooksLikeCase(full, out _, out _)) throw new CaseLocationRejectedException(NotACase);
        DriveType type;
        try { type = new DriveInfo(full[..3]).DriveType; }
        catch (Exception e) when (e is ArgumentException or IOException) { throw new CaseLocationRejectedException(NotACase); }
        if (type is not (DriveType.Fixed or DriveType.Removable)) throw new CaseLocationRejectedException("PCPorter only opens results on a drive connected to this PC.");
        if (!IsPlainFolder(full)) throw new CaseLocationRejectedException($"{full} is a link or is not on a normal folder path, so PCPorter will not change it.");
        if (!HasCaseDb(full)) throw new CaseLocationRejectedException(NotACase);
        if (FirstLinkInside(full) is { } link) throw new CaseLocationRejectedException($"{link} is a link to another location, so PCPorter will not change this folder.");
        return full;
    }

    /// <summary>The folder exists and neither it nor any folder above it is a link (checked from the drive down, links not followed).</summary>
    static bool IsPlainFolder(string folder)
    {
        var path = Path.TrimEndingDirectorySeparator(folder);
        if (path.Length == 2) path += "\\";
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') return false;
        return CaseLocation.ChainProblem(path, WindowsProbe.Instance, out var deepest) is null && deepest is not null
               && string.Equals(Path.TrimEndingDirectorySeparator(deepest), path, StringComparison.OrdinalIgnoreCase)
               && FileIdentity.Entry(path) is { } e && e.Attributes.HasFlag(FileAttributes.Directory);
    }

    static bool HasCaseDb(string folder) =>
        FileIdentity.Entry(Path.Combine(folder, "case.db")) is { IsReparsePoint: false } e && !e.Attributes.HasFlag(FileAttributes.Directory);

    /// <summary>The first link inside <paramref name="folder"/> (reparse point, or a file with more than one hard link), never following one.</summary>
    static string? FirstLinkInside(string folder)
    {
        var pending = new Stack<string>();
        pending.Push(folder);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            foreach (var entry in new DirectoryInfo(dir).EnumerateFileSystemInfos())
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) return entry.FullName;
                if (entry.Attributes.HasFlag(FileAttributes.Directory)) { pending.Push(entry.FullName); continue; }
                using var h = File.OpenHandle(entry.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (FileIdentity.LinkCount(h) is not 1) return entry.FullName;   // a hard link shares its permissions with a file elsewhere
            }
        }
        return null;
    }
}
