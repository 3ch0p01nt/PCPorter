using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Posture;

/// <summary>Checks that look at each user's registry (NTUSER.DAT).</summary>
public static class UserChecks
{
    static readonly string[] KfmFolders = ["Desktop", "Personal", "My Pictures"];

    // 2. Backups: OneDrive Known Folder Move, File History
    internal static PostureCheck Backup(PostureScan s)
    {
        const string id = PostureIds.Backup, title = "Backups";
        if (s.UserHives.Count == 0)
            return Make.Unknown(id, title, "We could not read any user's settings, so we cannot tell whether files are backed up.", $"{s.UsersWithoutHive} user hive(s) unreadable.");

        var ev = new List<string>();
        var unprotected = new List<string>();
        foreach (var (user, hive) in s.UserHives)
        {
            var profile = ProfileImagePath(s, user) ?? $@"{s.Source.OriginalSystemDrive}\Users\{user.UserName}";
            var oneDrive = new List<string>();
            PostureScan.With(hive, @"Software\Microsoft\OneDrive\Accounts", accounts =>
            {
                if (accounts is null) return 0;
                foreach (var a in accounts.SubKeys)
                {
                    try { if (a.GetString("UserFolder") is { Length: > 0 } f) oneDrive.Add(Normalize(f, profile)); }
                    finally { PostureScan.Dispose(a); }
                }
                return 0;
            });
            var moved = PostureScan.With(hive, @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", k =>
                k is null ? [] : KfmFolders.Where(f => k.GetString(f) is { } p && oneDrive.Any(od => IsInside(Normalize(p, profile), od))).ToList());
            var (fileHistory, protectedUpTo) = PostureScan.With(hive, @"Software\Microsoft\Windows\CurrentVersion\FileHistory", k =>
                (k is not null && (k.ValueNames.Any() || k.SubKeys.Any()), k is null ? null : FileTime(k.GetRaw("ProtectedUpToTime"))));
            ev.Add($"{user.UserName}: OneDrive folders={oneDrive.Count}, folders in OneDrive=[{string.Join(", ", moved)}], File History={(fileHistory ? "configured" : "not configured")}" +
                   (protectedUpTo is { } t ? $", ProtectedUpToTime={t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}" : ""));
            if (moved.Count == 0 && !fileHistory) unprotected.Add(user.UserName);
        }
        if (s.UsersWithoutHive > 0) ev.Add($"{s.UsersWithoutHive} user(s) could not be read.");
        var evidence = string.Join("; ", ev) + ". Other backup programs are not detected by this check.";

        if (unprotected.Count == 0)
            return Make.Good(id, title, "Every account we could read backs up its files (OneDrive folder backup or File History).", evidence);
        return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            unprotected.Count == s.UserHives.Count
                ? "We could not see an automatic backup (OneDrive folder backup or File History) for any account."
                : $"{unprotected.Count} of {s.UserHives.Count} accounts have no automatic backup we can see.",
            "If you use another backup program, you can ignore this. Otherwise turn on OneDrive folder backup (OneDrive settings > Sync and back up) or File History, so a broken drive does not cost you your files.", evidence);
    }

    static string? ProfileImagePath(PostureScan s, UserProfile user) =>
        PostureScan.With(s.Software, $@"Microsoft\Windows NT\CurrentVersion\ProfileList\{user.Sid}", k =>
            k?.GetString("ProfileImagePath") is { } p ? SourcePaths.Expand(p, s.Source.OriginalSystemDrive) : null);

    static string Normalize(string path, string profile)
    {
        var p = path.Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase);
        return p.Trim().Trim('"').TrimEnd('\\');
    }

    static bool IsInside(string path, string folder) =>
        folder.Length > 0 && (path.Equals(folder, StringComparison.OrdinalIgnoreCase) || path.StartsWith(folder + "\\", StringComparison.OrdinalIgnoreCase));

    static DateTimeOffset? FileTime((RegType Type, byte[] Raw)? v)
    {
        if (v is not { } x || x.Raw.Length < 8) return null;
        var ft = BinaryPrimitives.ReadInt64LittleEndian(x.Raw);
        if (ft <= 0) return null;
        try { return DateTimeOffset.FromFileTime(ft).ToUniversalTime(); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    // 6. Extra trusted root certificates
    internal static PostureCheck RootCertificates(PostureScan s)
    {
        const string id = PostureIds.RootCertificates, title = "Trusted certificates";
        var ev = new List<string>();
        var userAdded = new List<string>();
        foreach (var (user, hive) in s.UserHives)
        {
            var certs = PostureScan.With(hive, @"Software\Microsoft\SystemCertificates\Root\Certificates", k => k is null ? [] : Describe(k));
            if (certs.Count > 0) userAdded.Add($"{user.UserName}: {certs.Count}");
            foreach (var c in certs) ev.Add($"user {user.UserName} root: {c}");
        }
        var machine = PostureScan.With(s.Software, @"Microsoft\SystemCertificates\ROOT\Certificates", k => k?.SubKeys.Count());
        var policy = PostureScan.With(s.Software, @"Policies\Microsoft\SystemCertificates\Root\Certificates", k => k?.SubKeys.Count());
        ev.Insert(0, $"Machine root store: {Make.Num(machine)} certificate(s) (not judged); policy root store: {Make.Num(policy)}; users read: {s.UserHives.Count}, unreadable: {s.UsersWithoutHive}");
        var evidence = string.Join("; ", ev);
        var orgNote = policy is > 0 ? $" Your organization also added {policy} certificate(s) by policy, which is normal for work PCs." : "";

        if (userAdded.Count > 0)
            return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                $"Extra 'trusted' certificates were added for individual accounts ({string.Join(", ", userAdded)}).{orgNote}",
                "Developer tools, work VPNs and some security products add these. If you do not recognize them, ask someone technical to review them: a rogue one could let an attacker read secure web traffic.", evidence);
        if (s.UserHives.Count == 0 && machine is null)
            return Make.Unknown(id, title, "We could not read the trusted certificate lists.", evidence);
        if (s.UserHives.Count == 0)
            return Make.Unknown(id, title, "We could not read any user's certificate list." + orgNote, evidence);
        return Make.Good(id, title, "No extra trusted certificates were added for individual accounts." + orgNote, evidence);
    }

    /// <summary>Thumbprint plus subject when the stored blob holds a certificate (property 32).</summary>
    static List<string> Describe(IRegKey certificates)
    {
        var list = new List<string>();
        foreach (var c in certificates.SubKeys)
        {
            try
            {
                var subject = Subject(c.GetBytes("Blob"));
                list.Add(subject is null ? c.Name : $"{c.Name} ({subject})");
            }
            finally { PostureScan.Dispose(c); }
        }
        return list;
    }

    public static string? Subject(byte[]? blob)
    {
        if (blob is null) return null;
        int i = 0;
        while (i + 12 <= blob.Length)
        {
            var propId = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i));
            var len = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i + 8));
            i += 12;
            if (len > blob.Length - i) return null;
            if (propId == 32)
            {
                try
                {
                    using var cert = X509CertificateLoader.LoadCertificate(blob.AsSpan(i, (int)len));
                    return cert.Subject;
                }
                catch (CryptographicException) { return null; }
            }
            i += (int)len;
        }
        return null;
    }
}
