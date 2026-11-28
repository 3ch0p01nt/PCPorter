using System.Globalization;
using System.Text.RegularExpressions;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Posture;

/// <summary>Antivirus, sign-in and account checks.</summary>
public static partial class AccountChecks
{
    public const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    public const string WinlogonPath = @"Microsoft\Windows NT\CurrentVersion\Winlogon";

    // 4. Defender
    internal static PostureCheck Defender(PostureScan s) => s.IsLive ? DefenderLive(s) : DefenderOffline(s);

    static PostureCheck DefenderLive(PostureScan s)
    {
        const string id = PostureIds.Defender, title = "Microsoft Defender";
        var r = s.Query(DefenderNamespace,
            "SELECT AMRunningMode, AntivirusEnabled, IsTamperProtected, RealTimeProtectionEnabled, AntivirusSignatureAge FROM MSFT_MpComputerStatus");
        if (r.Outcome != WmiOutcome.Ok || r.Rows.Count == 0)
            return Make.Unknown(id, title, "We could not ask Microsoft Defender for its status.", $"MSFT_MpComputerStatus: {r.Outcome}, {r.Rows.Count} row(s).");
        var row = r.Rows[0];
        var mode = WmiValue.Str(row, "AMRunningMode");
        var tamper = WmiValue.Bool(row, "IsTamperProtected");
        var rtp = WmiValue.Bool(row, "RealTimeProtectionEnabled");
        var age = WmiValue.Long(row, "AntivirusSignatureAge");
        var evidence = $"AMRunningMode={mode ?? "(missing)"} IsTamperProtected={B(tamper)} RealTimeProtectionEnabled={B(rtp)} AntivirusSignatureAge={Make.Num(age)} day(s)";
        if (mode is null) return Make.Unknown(id, title, "We could not tell whether Microsoft Defender is the active antivirus.", evidence);
        if (!string.Equals(mode.Trim(), "Normal", StringComparison.OrdinalIgnoreCase))
            return Make.Check(id, title, PostureStatus.NotApplicable, PostureSeverity.Info,
                "Another antivirus product is in charge, so Microsoft Defender is on standby.",
                "Nothing to do here; make sure your other antivirus is up to date.", evidence);
        if (rtp == false) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
            "Microsoft Defender's real-time protection is off, so files are not scanned as you open them.",
            "Open Windows Security > Virus & threat protection > Manage settings and turn Real-time protection on.", evidence);
        var issues = new List<string>();
        if (tamper == false) issues.Add("Tamper Protection is off");
        if (age is > 7) issues.Add($"virus definitions are {age} days old");
        if (issues.Count > 0) return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"Microsoft Defender is running, but {string.Join(" and ", issues)}.",
            "Open Windows Security > Virus & threat protection: turn on Tamper Protection and select 'Check for updates' under protection updates.", evidence);
        if (tamper is null || rtp is null) return Make.Unknown(id, title, "Microsoft Defender is running, but some of its settings could not be read.", evidence);
        return Make.Good(id, title, "Microsoft Defender is running with real-time and tamper protection on.", evidence);
    }

    static PostureCheck DefenderOffline(PostureScan s)
    {
        const string id = PostureIds.Defender, title = "Microsoft Defender";
        var wd = s.Software?.Open(@"Microsoft\Windows Defender");
        if (wd is null) return Make.Unknown(id, title, "We could not find Microsoft Defender's settings on this drive.", @"SOFTWARE\Microsoft\Windows Defender missing.");
        try
        {
            var passive = wd.GetNumber("PassiveMode");
            var tamper = PostureScan.With(wd, "Features", k => k?.GetNumber("TamperProtection"));
            var rtOff = PostureScan.With(wd, "Real-Time Protection", k => k?.GetNumber("DisableRealtimeMonitoring"));
            var policyOff = PostureScan.With(s.Software, @"Policies\Microsoft\Windows Defender", k => k?.GetNumber("DisableAntiSpyware"));
            var evidence = $"PassiveMode={Make.Num(passive)} Features\\TamperProtection={Make.Num(tamper)} DisableRealtimeMonitoring={Make.Num(rtOff)} Policy DisableAntiSpyware={Make.Num(policyOff)}. Offline: whether Defender was the active antivirus cannot be confirmed from a drive.";
            if (passive == 1 || policyOff == 1)
                return Make.Check(id, title, PostureStatus.NotApplicable, PostureSeverity.Info,
                    "Microsoft Defender was set to stand by (another antivirus or your organization manages protection).",
                    "Nothing to do here; make sure the other antivirus is kept up to date.", evidence);
            if (rtOff == 1) return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
                "Microsoft Defender's real-time protection was switched off.",
                "On the PC, open Windows Security > Virus & threat protection > Manage settings and turn Real-time protection on.", evidence);
            return tamper switch
            {
                5 => Make.Good(id, title, "Microsoft Defender's Tamper Protection is on.", evidence),
                null => Make.Unknown(id, title, "We could not tell whether Tamper Protection is on.", evidence),
                _ => Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                    "Microsoft Defender's Tamper Protection is off, so malware could switch Defender off.",
                    "On the PC, open Windows Security > Virus & threat protection > Manage settings and turn on Tamper Protection.", evidence),
            };
        }
        finally { PostureScan.Dispose(wd); }
    }

    static string B(bool? b) => b is null ? "(missing)" : b.Value ? "True" : "False";

    // 7. Auto-logon. The DefaultPassword VALUE is never read: only its NAME is looked for in ValueNames.
    internal static PostureCheck AutoLogon(PostureScan s)
    {
        const string id = PostureIds.AutoLogon, title = "Automatic sign-in";
        var wl = s.Software?.Open(WinlogonPath);
        if (wl is null) return Make.Unknown(id, title, "We could not read the sign-in settings.", @"Winlogon key missing.");
        try
        {
            var auto = wl.GetString("AutoAdminLogon")?.Trim();
            var names = wl.ValueNames.ToList();
            bool hasPassword = names.Any(n => string.Equals(n, "DefaultPassword", StringComparison.OrdinalIgnoreCase));
            bool hasUser = names.Any(n => string.Equals(n, "DefaultUserName", StringComparison.OrdinalIgnoreCase));
            var evidence = $"AutoAdminLogon={auto ?? "(not set)"}; a value named DefaultPassword {(hasPassword ? "exists" : "does not exist")} (its contents were not read); DefaultUserName {(hasUser ? "is set" : "is not set")}.";
            if (auto == "1")
                return Make.Check(id, title, PostureStatus.Risk, PostureSeverity.High,
                    hasPassword
                        ? "Windows signs in automatically, and a password is saved in the registry in a readable form."
                        : "Windows signs in automatically, so anyone who turns the PC on gets into the account.",
                    "If you do not need this, turn it off: run 'netplwiz' and tick 'Users must enter a user name and password'. Then consider changing that account's password.", evidence);
            if (hasPassword)
                return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                    "Automatic sign-in is off, but an old saved sign-in password is still stored in the registry.",
                    "Consider changing that account's password. Someone technical can remove the leftover 'DefaultPassword' entry.", evidence);
            return Make.Good(id, title, "Windows does not sign in automatically.", evidence);
        }
        finally { PostureScan.Dispose(wl); }
    }

    [GeneratedRegex("""Domain="(?<d>[^"]*)",Name="(?<n>[^"]*)"$""")] private static partial Regex PartComponentKeys();
    [GeneratedRegex("""(?<cls>Win32_\w+)\.Domain=""")] private static partial Regex PartComponentClass();

    /// <summary>Parses a WMI reference like \\PC\root\cimv2:Win32_UserAccount.Domain="PC",Name="bob". Null when malformed.</summary>
    public static (string Class, string Domain, string Name)? ParseMember(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var keys = PartComponentKeys().Match(path);
        var cls = PartComponentClass().Match(path);
        if (!keys.Success || !cls.Success) return null;
        return (cls.Groups["cls"].Value, keys.Groups["d"].Value, keys.Groups["n"].Value);
    }

    // 8. Local admins / password not required (live only; never touches SAM)
    internal static PostureCheck LocalAccounts(PostureScan s)
    {
        const string id = PostureIds.LocalAccounts, title = "Local accounts";
        if (!s.IsLive) return Make.LiveOnlyUnknown(id, title);
        var users = s.Query(@"root\cimv2", "SELECT Name, SID, Disabled, PasswordRequired, LocalAccount FROM Win32_UserAccount WHERE LocalAccount=TRUE");
        if (users.Outcome != WmiOutcome.Ok)
            return Make.Unknown(id, title, "We could not list this PC's accounts.", $"Win32_UserAccount: {users.Outcome}", true);

        var accounts = users.Rows.Select(r => (Name: WmiValue.Str(r, "Name") ?? "?", Sid: WmiValue.Str(r, "SID") ?? "",
            Disabled: WmiValue.Bool(r, "Disabled"), PasswordRequired: WmiValue.Bool(r, "PasswordRequired"))).ToList();
        var enabled = accounts.Where(a => a.Disabled == false).ToList();
        var noPassword = enabled.Where(a => a.PasswordRequired == false).ToList();
        var builtinAdmin = enabled.Where(a => a.Sid.EndsWith("-500", StringComparison.Ordinal)).ToList();

        // Administrators group: found by its well-known SID (its name is translated on non-English Windows).
        var admins = new List<string>();
        string adminNote;
        var group = s.Query(@"root\cimv2", "SELECT Name, Domain FROM Win32_Group WHERE LocalAccount=TRUE AND SID='S-1-5-32-544'");
        var g = group.Outcome == WmiOutcome.Ok ? group.Rows.FirstOrDefault() : null;
        var gName = g is null ? null : WmiValue.Str(g, "Name");
        var gDomain = g is null ? null : WmiValue.Str(g, "Domain");
        if (gName is null || gDomain is null || gName.Contains('\'') || gDomain.Contains('\''))
            adminNote = $"Administrators group not resolved ({group.Outcome}).";
        else
        {
            var members = s.Query(@"root\cimv2", $"SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='{gDomain}',Name='{gName}'\"");
            if (members.Outcome == WmiOutcome.Ok)
            {
                foreach (var m in members.Rows)
                    if (ParseMember(WmiValue.Str(m, "PartComponent")) is { } p)
                        admins.Add((p.Class == "Win32_Group" ? "group " : "") + (string.Equals(p.Domain, gDomain, StringComparison.OrdinalIgnoreCase) ? p.Name : $"{p.Domain}\\{p.Name}"));
                adminNote = $"Administrators members: {admins.Count}.";
            }
            else adminNote = $"Administrators members not listed ({members.Outcome}).";
        }

        var evidence = $"Local accounts: {accounts.Count} ({enabled.Count} enabled). Enabled accounts that may have no password: " +
            (noPassword.Count == 0 ? "none" : string.Join(", ", noPassword.Select(a => a.Name))) +
            $". Built-in Administrator enabled: {(builtinAdmin.Count > 0 ? "yes" : "no")}. {adminNote}" +
            (admins.Count > 0 ? " Members: " + string.Join(", ", admins) + "." : "");

        var issues = new List<string>();
        if (noPassword.Count > 0) issues.Add($"{noPassword.Count} enabled account(s) may have no password ({string.Join(", ", noPassword.Select(a => a.Name))})");
        if (builtinAdmin.Count > 0) issues.Add("the built-in Administrator account is switched on");
        if (issues.Count > 0) return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"On this PC, {string.Join(" and ", issues)}.",
            "Give every account you use a password (Settings > Accounts > Sign-in options), and switch off accounts nobody uses.", evidence, true);
        if (accounts.Any(a => a.Disabled is null || (a.Disabled == false && a.PasswordRequired is null)))
            return Make.Unknown(id, title, "Some account details could not be read.", evidence, true);
        return Make.Good(id, title, $"{enabled.Count} account(s) are switched on, and all of them require a password.", evidence, true);
    }

    internal static string Invariant(long v) => v.ToString(CultureInfo.InvariantCulture);
}
