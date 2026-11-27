using System.Globalization;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Posture;

/// <summary>Short constructors so each check reads like its rules.</summary>
internal static class Make
{
    public const string NothingToDo = "Nothing to do.";

    public static PostureCheck Check(string id, string title, PostureStatus status, PostureSeverity severity, string finding, string advice, string evidence, bool liveOnly = false) =>
        new(id, title, status, severity, finding, advice, evidence, liveOnly);

    public static PostureCheck Good(string id, string title, string finding, string evidence, bool liveOnly = false) =>
        new(id, title, PostureStatus.Good, PostureSeverity.Info, finding, NothingToDo, evidence, liveOnly);

    public static PostureCheck Unknown(string id, string title, string finding, string evidence, bool liveOnly = false) =>
        new(id, title, PostureStatus.Unknown, PostureSeverity.Info, finding,
            "Nothing to do now. If you want to be sure, check this setting on the PC itself.", evidence, liveOnly);

    public static PostureCheck LiveOnlyUnknown(string id, string title) =>
        new(id, title, PostureStatus.Unknown, PostureSeverity.Info,
            "This can only be checked while the PC itself is running, not from its drive.",
            "Run PCPorter on the PC itself if you want this check.", "Offline scan: live-only check skipped.", true);

    public static string Num(long? v) => v?.ToString(CultureInfo.InvariantCulture) ?? "(not set)";
}

/// <summary>Machine-wide checks read from SOFTWARE and SYSTEM (live and offline).</summary>
public static class SystemChecks
{
    const string CurrentVersion = @"Microsoft\Windows NT\CurrentVersion";

    // 1. End-of-support Windows
    internal static PostureCheck WindowsSupport(PostureScan s)
    {
        const string id = PostureIds.WindowsSupport, title = "Windows support";
        var cv = s.Software?.Open(CurrentVersion);
        if (cv is null) return Make.Unknown(id, title, "We could not read which Windows version this is.", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion missing.");
        try
        {
            var buildText = cv.GetString("CurrentBuild") ?? cv.GetString("CurrentBuildNumber");
            int? build = int.TryParse(buildText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var b) ? b : null;
            var ubr = cv.GetNumber("UBR");
            var display = cv.GetString("DisplayVersion") ?? cv.GetString("ReleaseId");
            var edition = cv.GetString("EditionID");
            var evidence = $"CurrentBuild={buildText ?? "(missing)"} UBR={Make.Num(ubr)} DisplayVersion={display ?? "(missing)"} EditionID={edition ?? "(missing)"}";
            var v = WindowsLifecycle.Evaluate(build, edition, s.Today);
            var name = build is { } bn ? $"{WindowsLifecycle.ProductForBuild(bn)} {v.Entry?.Version ?? display}".Trim() : "this Windows version";
            var trackText = v.Track == EditionTrack.EnterpriseEducation ? "Enterprise/Education" : "Home/Pro";
            var end = v.EndDate?.ToString("d MMMM yyyy", CultureInfo.InvariantCulture);
            evidence += $" Track={v.Track} End={v.EndDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "-"} (support table as of 2026-11)";
            return v.State switch
            {
                SupportState.Supported => Make.Good(id, title, $"{name} ({trackText}) gets security updates until {end}.", evidence),
                SupportState.EndingSoon => Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                    $"{name} ({trackText}) stops getting security updates on {end}.",
                    "Plan to install the newer Windows version (Settings > Windows Update) before that date. It is free on supported PCs.", evidence),
                SupportState.ExtendedSecurityUpdates => Make.Check(id, title, PostureStatus.Attention, PostureSeverity.High,
                    $"Regular support for {name} has ended. Extended Security Updates are available until {end}, if this PC is enrolled.",
                    "Make sure the PC is enrolled in Extended Security Updates, and plan a move to Windows 11 or a new PC before that date.", evidence),
                SupportState.Ended => Make.Check(id, title, PostureStatus.Risk, PostureSeverity.Critical,
                    $"{name} no longer gets security updates from Microsoft (support ended {end}).",
                    "The PC still works, but new security holes will not be fixed. Upgrade Windows (Settings > Windows Update) or move to a new PC; PCPorter can help you move.", evidence),
                _ => Make.Unknown(id, title, $"We could not match this Windows version to Microsoft's support dates. {v.Reason}", evidence),
            };
        }
        finally { PostureScan.Dispose(cv); }
    }

    // 3. Windows Update recency
    internal static PostureCheck WindowsUpdate(PostureScan s)
    {
        const string id = PostureIds.WindowsUpdate, title = "Windows updates";
        DateTimeOffset? newest = null;
        string evidence;
        if (s.IsLive)
        {
            var r = s.Query(@"root\cimv2", "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
            if (r.Outcome == WmiOutcome.Ok)
            {
                int parsed = 0;
                foreach (var row in r.Rows)
                    if (ParseInstalledOn(WmiValue.Str(row, "InstalledOn")) is { } d) { parsed++; if (newest is null || d > newest) newest = d; }
                evidence = $"Win32_QuickFixEngineering: {r.Rows.Count} update(s), {parsed} with a readable date.";
            }
            else
            {
                evidence = $"Win32_QuickFixEngineering failed ({r.Outcome}); used servicing package dates instead (approximation).";
                newest = NewestPackageWrite(s, out var n);
                evidence += $" {n} package key(s).";
            }
        }
        else
        {
            newest = NewestPackageWrite(s, out var n);
            evidence = $"Offline approximation: newest last-write time of {n} Component Based Servicing package key(s); this can also change for reasons other than updates.";
        }

        if (newest is not { } when) return Make.Unknown(id, title, "We could not tell when Windows last installed updates.", evidence);
        var days = (int)Math.Floor((s.Now - when).TotalDays);
        evidence += $" Newest={when.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)} ({days} day(s) ago).";
        if (days < -2) return Make.Unknown(id, title, "The update dates on this PC are in the future, so we cannot tell when it was last updated.", evidence);
        if (days > 90) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            $"Windows does not seem to have installed updates for about {days} days.",
            "Open Settings > Windows Update and select 'Check for updates'. If updates keep failing, that is worth fixing before moving your files.", evidence);
        if (days > 45) return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"The last Windows update we can see is about {days} days old.",
            "Open Settings > Windows Update and select 'Check for updates'. Updates may simply be paused.", evidence);
        return Make.Good(id, title, "Windows installed updates " + (days == 0 ? "today." : days == 1 ? "yesterday." : $"{days} days ago."), evidence);
    }

    /// <summary>InstalledOn is usually M/d/yyyy (invariant), sometimes yyyyMMdd or a hex FILETIME.</summary>
    public static DateTimeOffset? ParseInstalledOn(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        string[] formats = ["M/d/yyyy", "MM/dd/yyyy", "M/d/yyyy h:mm:ss tt", "M/d/yyyy H:mm:ss", "yyyyMMdd", "yyyy-MM-dd", "yyyy-MM-ddTHH:mm:ss"];
        if (DateTime.TryParseExact(t, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d))
            return new DateTimeOffset(d, TimeSpan.Zero);
        if (t.Length == 16 && long.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ft) && ft > 0)
        {
            try { return DateTimeOffset.FromFileTime(ft).ToUniversalTime(); }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        return null;
    }

    static DateTimeOffset? NewestPackageWrite(PostureScan s, out int count)
    {
        count = 0;
        var packages = s.Software?.Open(@"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
        if (packages is null) return null;
        DateTimeOffset? newest = null;
        try
        {
            foreach (var k in packages.SubKeys)
            {
                count++;
                try { if (k.LastWrite is { } lw && (newest is null || lw > newest)) newest = lw; }
                finally { PostureScan.Dispose(k); }
            }
        }
        finally { PostureScan.Dispose(packages); }
        return newest;
    }

    // 5. Firewall
    internal static PostureCheck Firewall(PostureScan s)
    {
        const string id = PostureIds.Firewall, title = "Firewall";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read the firewall settings.", "SYSTEM hive or control set missing.");
        var policy = @"Services\SharedAccess\Parameters\FirewallPolicy";
        var profiles = new (string Key, string PolicyKey, string Friendly)[]
        {
            ("DomainProfile", "DomainProfile", "work network (domain)"),
            ("StandardProfile", "PrivateProfile", "home/private network"),
            ("PublicProfile", "PublicProfile", "public network"),
        };
        var ev = new List<string>();
        var state = new Dictionary<string, bool?>();
        foreach (var (key, policyKey, _) in profiles)
        {
            var local = PostureScan.With(s.ControlSet, $@"{policy}\{key}", k => k?.GetNumber("EnableFirewall"));
            var gp = PostureScan.With(s.Software, $@"Policies\Microsoft\WindowsFirewall\{policyKey}", k => k?.GetNumber("EnableFirewall"));
            if (gp is null && key == "StandardProfile")
                gp = PostureScan.With(s.Software, @"Policies\Microsoft\WindowsFirewall\StandardProfile", k => k?.GetNumber("EnableFirewall"));
            var effective = gp ?? local;
            state[key] = effective is null ? null : effective != 0;
            ev.Add($"{key}: EnableFirewall={Make.Num(local)} policy={Make.Num(gp)}");
        }
        var svcStart = PostureScan.With(s.ControlSet, @"Services\MpsSvc", k => k?.GetNumber("Start"));
        ev.Add($"MpsSvc Start={Make.Num(svcStart)}");
        var evidence = string.Join("; ", ev);

        if (svcStart == 4) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            "The Windows Firewall service is switched off.",
            "This is a setting, not broken hardware. Unless another security product manages the firewall, turn Windows Firewall back on (Windows Security > Firewall & network protection).", evidence);
        var off = profiles.Where(p => state[p.Key] == false).ToList();
        if (off.Any(p => p.Key is "StandardProfile" or "PublicProfile"))
            return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
                $"The firewall is off for: {string.Join(", ", off.Select(p => p.Friendly))}.",
                "This is a setting, not broken hardware. Turn it back on in Windows Security > Firewall & network protection, unless another security product manages your firewall.", evidence);
        if (off.Count > 0)
            return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Low,
                "The firewall is off for work (domain) networks only.",
                "If this PC is managed by your work, that may be intentional. Otherwise turn it back on in Windows Security > Firewall & network protection.", evidence);
        if (state.Values.Any(v => v is null))
            return Make.Unknown(id, title, "Some firewall settings were not recorded, so we cannot confirm the firewall is on everywhere.", evidence);
        return Make.Good(id, title, "The firewall is on for every type of network.", evidence);
    }

    // 11. SMB1
    internal static PostureCheck Smb1(PostureScan s)
    {
        const string id = PostureIds.Smb1, title = "Old file sharing (SMB1)";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read the file sharing settings.", "SYSTEM hive or control set missing.");
        var clientStart = PostureScan.With(s.ControlSet, @"Services\mrxsmb10", k => k is null ? (long?)null : k.GetNumber("Start") ?? -1);
        var serverValue = PostureScan.With(s.ControlSet, @"Services\LanmanServer\Parameters", k => k?.GetNumber("SMB1"));
        var srvStart = PostureScan.With(s.ControlSet, @"Services\srv", k => k is null ? (long?)null : k.GetNumber("Start") ?? -1);
        var evidence = $"mrxsmb10 Start={(clientStart is null ? "(not installed)" : Make.Num(clientStart))}; LanmanServer SMB1={Make.Num(serverValue)}; srv Start={(srvStart is null ? "(not installed)" : Make.Num(srvStart))}";
        var reasons = new List<string>();
        if (clientStart is { } c && c != 4) reasons.Add("the SMB1 client is turned on");
        if (serverValue == 1) reasons.Add("the SMB1 server is switched on");
        else if (srvStart is { } sv && sv != 4 && serverValue != 0) reasons.Add("the SMB1 server component is installed and not switched off");
        if (reasons.Count > 0) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            $"An old, insecure way of sharing files is enabled: {string.Join("; ", reasons)}.",
            "Very old network drives or printers may still need it; otherwise turn off 'SMB 1.0/CIFS File Sharing Support' in Windows Features. This is a setting, not broken hardware.", evidence);
        return Make.Good(id, title, "The old SMB1 file sharing protocol is off.", evidence);
    }

    // 12. Remote Desktop
    internal static PostureCheck RemoteDesktop(PostureScan s)
    {
        const string id = PostureIds.RemoteDesktop, title = "Remote Desktop";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read the Remote Desktop settings.", "SYSTEM hive or control set missing.");
        var deny = PostureScan.With(s.ControlSet, @"Control\Terminal Server", k => k?.GetNumber("fDenyTSConnections"));
        var policyDeny = PostureScan.With(s.Software, @"Policies\Microsoft\Windows NT\Terminal Services", k => k?.GetNumber("fDenyTSConnections"));
        var (nla, port) = PostureScan.With(s.ControlSet, @"Control\Terminal Server\WinStations\RDP-Tcp", k => (k?.GetNumber("UserAuthentication"), k?.GetNumber("PortNumber")));
        var effective = policyDeny ?? deny;
        var evidence = $"fDenyTSConnections={Make.Num(deny)} policy={Make.Num(policyDeny)} UserAuthentication(NLA)={Make.Num(nla)} PortNumber={Make.Num(port)}";
        if (effective is null) return Make.Unknown(id, title, "We could not tell whether Remote Desktop is on.", evidence);
        if (effective != 0) return Make.Good(id, title, "Remote Desktop (connecting to this PC from elsewhere) is off.", evidence);
        var portText = port is { } p && p != 3389 ? $" on a non-standard port ({p})" : "";
        if (nla == 0) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            $"Remote Desktop is on{portText} and does not ask who you are before showing the sign-in screen.",
            "If you do not use Remote Desktop, turn it off (Settings > System > Remote Desktop). If you do, turn on 'Require devices to use Network Level Authentication'.", evidence);
        return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Low,
            $"Remote Desktop is on{portText}, so this PC accepts remote sign-ins.",
            "That is fine if you use it. If you do not, turn it off in Settings > System > Remote Desktop.", evidence);
    }

    // 13. UAC
    internal static PostureCheck Uac(PostureScan s)
    {
        const string id = PostureIds.Uac, title = "User Account Control";
        var (lua, consent, secure) = PostureScan.With(s.Software, @"Microsoft\Windows\CurrentVersion\Policies\System",
            k => (k?.GetNumber("EnableLUA"), k?.GetNumber("ConsentPromptBehaviorAdmin"), k?.GetNumber("PromptOnSecureDesktop")));
        var evidence = $"EnableLUA={Make.Num(lua)} ConsentPromptBehaviorAdmin={Make.Num(consent)} PromptOnSecureDesktop={Make.Num(secure)}";
        if (lua is null) return Make.Unknown(id, title, "We could not read the User Account Control setting.", evidence);
        if (lua == 0) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.Critical,
            "User Account Control is switched off, so every program runs with full control of the PC.",
            "This is a setting, not broken hardware. Turn it back on: search Start for 'Change User Account Control settings', move the slider up, then restart.", evidence);
        if (consent == 0) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            "Programs can get administrator rights without asking you first.",
            "Search Start for 'Change User Account Control settings' and choose the default level ('Notify me only when apps try to make changes').", evidence);
        return Make.Good(id, title, "User Account Control is on and asks before programs make big changes.", evidence);
    }

    // 15a. Memory integrity (HVCI)
    internal static PostureCheck MemoryIntegrity(PostureScan s)
    {
        const string id = PostureIds.MemoryIntegrity, title = "Memory integrity";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read this setting.", "SYSTEM hive or control set missing.");
        var enabled = PostureScan.With(s.ControlSet, @"Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", k => k?.GetNumber("Enabled"));
        var evidence = $"HypervisorEnforcedCodeIntegrity Enabled={Make.Num(enabled)}";
        return enabled switch
        {
            1 => Make.Good(id, title, "Memory integrity (Core isolation) is on.", evidence),
            0 => Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Low, "Memory integrity (Core isolation) is off.",
                "Optional extra protection. You can turn it on in Windows Security > Device security > Core isolation; an older driver may block it.", evidence),
            null => Make.Unknown(id, title, "Memory integrity has no recorded setting, so we cannot tell whether it is on.", evidence),
            _ => Make.Unknown(id, title, "Memory integrity has an unexpected setting.", evidence),
        };
    }

    // 15b. LSA protection
    internal static PostureCheck LsaProtection(PostureScan s)
    {
        const string id = PostureIds.LsaProtection, title = "Sign-in secrets protection";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read this setting.", "SYSTEM hive or control set missing.");
        var (ppl, boot) = PostureScan.With(s.ControlSet, @"Control\Lsa", k => (k?.GetNumber("RunAsPPL"), k?.GetNumber("RunAsPPLBoot")));
        var evidence = $"Lsa RunAsPPL={Make.Num(ppl)} RunAsPPLBoot={Make.Num(boot)}";
        if (ppl is 1 or 2 || boot is 1 or 2) return Make.Good(id, title, "Local Security Authority protection is on.", evidence);
        if (ppl == 0) return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Low,
            "Local Security Authority protection (which guards saved sign-in secrets) is off.",
            "Optional extra protection. You can turn it on in Windows Security > Device security > Core isolation > Local Security Authority protection.", evidence);
        return Make.Unknown(id, title, "This protection has no recorded setting; Windows may manage it automatically.", evidence);
    }

    // 15c. Smart App Control
    internal static PostureCheck SmartAppControl(PostureScan s)
    {
        const string id = PostureIds.SmartAppControl, title = "Smart App Control";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read this setting.", "SYSTEM hive or control set missing.");
        var state = PostureScan.With(s.ControlSet, @"Control\CI\Policy", k => k?.GetNumber("VerifiedAndReputablePolicyState"));
        var evidence = $"VerifiedAndReputablePolicyState={Make.Num(state)} (0 off, 1 on, 2 evaluation)";
        return state switch
        {
            1 => Make.Good(id, title, "Smart App Control is on and blocks untrusted apps.", evidence),
            2 => Make.Good(id, title, "Smart App Control is in evaluation mode: Windows is checking whether it suits how you use this PC.", evidence),
            0 => Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Info, "Smart App Control is off.",
                "No action needed; this is the norm on most PCs. Switching it on later needs a fresh Windows install, so consider it when setting up your new PC.", evidence),
            null when s.Build() is { } b && b < 22621 => Make.Check(id, title, PostureStatus.NotApplicable, PostureSeverity.Info,
                "This version of Windows does not have Smart App Control.", Make.NothingToDo, evidence),
            _ => Make.Unknown(id, title, "We could not tell whether Smart App Control is on.", evidence),
        };
    }

    // 16. Pending reboot
    internal static PostureCheck PendingReboot(PostureScan s)
    {
        const string id = PostureIds.PendingReboot, title = "Restart pending";
        if (s.Software is null && s.ControlSet is null) return Make.Unknown(id, title, "We could not tell whether a restart is pending.", "SOFTWARE and SYSTEM hives missing.");
        bool cbs = PostureScan.With(s.Software, @"Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", k => k is not null);
        bool wu = PostureScan.With(s.Software, @"Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", k => k is not null);
        int renames = PostureScan.With(s.ControlSet, @"Control\Session Manager", k => k?.GetMulti("PendingFileRenameOperations")?.Count(x => x.Length > 0) ?? 0);
        var evidence = $"CBS RebootPending={(cbs ? "present" : "absent")}; WindowsUpdate RebootRequired={(wu ? "present" : "absent")}; PendingFileRenameOperations entries={renames}";
        var why = new List<string>();
        if (cbs || wu) why.Add("Windows updates are waiting to finish");
        if (renames > 0) why.Add("some files are waiting to be replaced");
        if (why.Count == 0) return Make.Good(id, title, "No restart is waiting.", evidence);
        return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Low,
            $"The PC is waiting for a restart: {string.Join(" and ", why)}.",
            "Restart the PC when convenient (before moving files is a good moment).", evidence);
    }

    // 17. Free disk space
    internal static PostureCheck DiskSpace(PostureScan s)
    {
        const string id = PostureIds.DiskSpace, title = "Free disk space";
        var drives = new List<(string Name, long Free, long Total)>();
        string source;
        if (s.IsLive && s.Options.DriveSpace is null)
        {
            var r = s.Query(@"root\cimv2", "SELECT DeviceID, FreeSpace, Size FROM Win32_LogicalDisk WHERE DriveType=3");
            if (r.Outcome == WmiOutcome.Ok)
            {
                foreach (var row in r.Rows)
                    if (WmiValue.Long(row, "FreeSpace") is { } f && WmiValue.Long(row, "Size") is { } t && t > 0)
                        drives.Add((WmiValue.Str(row, "DeviceID") ?? "?", f, t));
                source = "Win32_LogicalDisk (fixed drives)";
            }
            else source = $"Win32_LogicalDisk failed ({r.Outcome})";
            if (drives.Count == 0 && DriveSpaceOf(s.Source.ReadRoot) is { } d) { drives.Add((s.Source.OriginalSystemDrive, d.Free, d.Total)); source += "; system drive via DriveInfo"; }
        }
        else
        {
            var space = (s.Options.DriveSpace ?? DriveSpaceOf)(s.Source.ReadRoot);
            if (space is { } d && d.Total > 0) drives.Add((s.Source.OriginalSystemDrive, d.Free, d.Total));
            source = "system drive via DriveInfo";
        }
        if (drives.Count == 0) return Make.Unknown(id, title, "We could not read how much free space the drive has.", source);
        var evidence = source + ": " + string.Join("; ", drives.Select(d => $"{d.Name} {Gb(d.Free)} free of {Gb(d.Total)} ({Pct(d)}%)"));
        var low = drives.Where(d => d.Free * 10 < d.Total).ToList();
        if (low.Count > 0) return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"Drive {string.Join(", ", low.Select(d => d.Name))} has less than 10% free space ({string.Join(", ", low.Select(d => Gb(d.Free) + " free"))}).",
            "A nearly full drive can stop Windows updates from installing. Empty the Recycle Bin and use Settings > System > Storage to clean up.", evidence);
        return Make.Good(id, title, "Every drive has at least 10% free space.", evidence);

        static string Gb(long b) => (b / 1024d / 1024 / 1024).ToString("0.#", CultureInfo.InvariantCulture) + " GB";
        static string Pct((string, long Free, long Total) d) => (d.Free * 100d / d.Total).ToString("0", CultureInfo.InvariantCulture);
    }

    static (long Free, long Total)? DriveSpaceOf(string root)
    {
        try
        {
            var di = new DriveInfo(root);
            return di.IsReady ? (di.AvailableFreeSpace, di.TotalSize) : null;
        }
        catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException) { return null; }
    }
}
