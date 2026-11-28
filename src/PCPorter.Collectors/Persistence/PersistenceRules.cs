using System.Text.RegularExpressions;

namespace PCPorter.Collectors.Persistence;

/// <param name="PayloadPath">The payload as the scanned PC knows it, env vars expanded where known (null if inline/none).</param>
public sealed record RuleInput(PersistenceEntry Entry, ParsedCommand Command, string? PayloadPath, SignatureInfo Signature);

public sealed record RuleResult(string RuleId, Severity Severity, string Reason, bool Disabled);

/// <summary>
/// Scores an autostart entry. Rules are evaluated top-down and the first match wins (plan Task 7a table).
/// Pure: no file system, registry or signature access.
/// </summary>
public static class PersistenceRules
{
    public static readonly string[] AccessibilityTools = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"];

    static readonly string[] DebuggerAllowlist =
        ["procexp.exe", "procexp64.exe", "procexp64a.exe", "vsjitdebugger.exe", "windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe", "devenv.exe"];

    static readonly (string Pattern, string What)[] SuspiciousPatterns =
    [
        (@"(?<![\w-])[-/]enc(odedcommand)?\b|(?<![\w-])[-/]encodedcommand\b", "an encoded PowerShell command (-enc)"),
        (@"(?<![\w-])iex\b|invoke-expression", "Invoke-Expression (iex)"),
        (@"frombase64string", "FromBase64String"),
        (@"(?<![\w-])iwr\b|invoke-webrequest|(?<![\w-])curl(\.exe)?\s+[^\r\n]*https?://", "a download command (iwr/Invoke-WebRequest/curl)"),
        (@"mshta(\.exe)?""?\s+""?https?:", "mshta loading a web page"),
        (@"rundll32(\.exe)?""?\s+[^\r\n]*javascript:", "rundll32 running JavaScript"),
        (@"regsvr32(\.exe)?""?\s+[^\r\n]*[-/]i:\s*""?https?", "regsvr32 loading a script from the internet"),
        (@"certutil(\.exe)?""?\s+[^\r\n]*[-/]urlcache", "certutil downloading a file"),
        (@"bitsadmin(\.exe)?""?\s+[^\r\n]*[-/]transfer", "bitsadmin downloading a file"),
        // Weak signs last, so a command with both reports the strong one (see IsWeakPattern).
        (@"(?<![\w-])[-/]w(in(dow)?(style)?)?\s+hid(den)?\b", "a hidden window switch (-w hidden)"),
        (@"(?<![\w-])[-/]nop\b", "the -nop switch"),
    ];

    static readonly Regex[] SuspiciousRegexes =
        SuspiciousPatterns.Select(p => new Regex(p.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200))).ToArray();

    static readonly string[] ScriptExtensions = [".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf"];

    /// <summary>OEM allowlist: signer substring + path prefixes (drive-less, lower-case).</summary>
    static readonly (string[] Signers, string[] Prefixes)[] OemAllowlist =
    [
        (["HP Inc", "Hewlett-Packard", "HP Development"], [@"\program files\hp\", @"\program files (x86)\hp\", @"\program files\hewlett-packard\", @"\program files (x86)\hewlett-packard\", DriverStore]),
        (["Dell"], [@"\program files\dell\", @"\program files (x86)\dell\", DriverStore]),
        (["Lenovo"], [@"\program files\lenovo\", @"\program files (x86)\lenovo\", DriverStore]),
        (["ASUSTeK", "ASUS"], [@"\program files\asus\", @"\program files (x86)\asus\", DriverStore]),
        (["Realtek"], [@"\program files\realtek\", @"\program files (x86)\realtek\", DriverStore]),
        (["Intel Corporation", "Intel(R)"], [@"\program files\intel\", @"\program files (x86)\intel\", @"\program files\common files\intel\", DriverStore]),
        (["NVIDIA"], [@"\program files\nvidia corporation\", @"\program files (x86)\nvidia corporation\", DriverStore]),
        (["Advanced Micro Devices", "AMD"], [@"\program files\amd\", @"\program files (x86)\amd\", @"\program files\ati technologies\", DriverStore]),
        (["Logitech"], [@"\program files\logitech\", @"\program files (x86)\logitech\", @"\program files\logi\", @"\program files (x86)\logi\", DriverStore]),
    ];

    const string DriverStore = @"\windows\system32\driverstore\filerepository\";

    public static RuleResult Score(RuleInput input)
    {
        var (id, severity, reason) = FirstMatch(input);
        var e = input.Entry;
        if (!string.IsNullOrWhiteSpace(e.Note)) reason += " " + e.Note.Trim();
        if (e.Disabled)
        {
            severity = Lower(severity);
            reason += " It is turned off, so it does not run at the moment.";
        }
        return new RuleResult(id, severity, reason, e.Disabled);
    }

    public static Severity Lower(Severity s) => s == Severity.Hidden ? Severity.Hidden : s - 1;

    static (string, Severity, string) FirstMatch(RuleInput i)
    {
        var e = i.Entry;
        var sig = i.Signature;
        var path = NormalizePath(i.PayloadPath);
        var file = FileName(path);
        bool unsigned = sig.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid;
        bool valid = sig.Status == SignatureStatus.Valid;
        string signer = string.IsNullOrWhiteSpace(sig.Signer) ? "its publisher" : sig.Signer!;

        // 1
        if (e.Kind == EntryKind.WmiConsumer)
            return ("WMI_CONSUMER", Severity.High, "A WMI event subscription runs this automatically. This is rare on home PCs and is a common way for malware to hide.");
        // 2
        if (e.Kind == EntryKind.Accessibility && (unsigned || (valid && !sig.IsMicrosoft)))
            return ("ACCESSIBILITY_REPLACED", Severity.High, $"The accessibility tool {e.Name} is not the Microsoft original. Replacing it is a known way to get into a PC without a password.");
        // 3
        if (e.Kind == EntryKind.IfeoDebugger)
        {
            if (valid && (sig.IsMicrosoft || (sig.Signer?.Contains("Sysinternals", StringComparison.OrdinalIgnoreCase) ?? false)) && DebuggerAllowlist.Contains(file))
                return ("IFEO_DEBUGGER", Severity.Low, $"A signed debugging tool ({file}) is set to start with {e.Name}. Developers and Process Explorer do this on purpose.");
            return ("IFEO_DEBUGGER", Severity.High, $"Whenever {e.Name} runs (or exits), Windows starts this program as well. This setting is often misused by malware.");
        }
        // 4
        if (e.Kind == EntryKind.Winlogon)
            return ("WINLOGON_CHANGED", Severity.High, $"A Windows sign-in or startup setting ({e.Name}) is different from the Windows default.");
        // 5
        if (e.Kind == EntryKind.DllInjection)
            return ("DLL_INJECTION", Severity.High, $"This DLL is loaded into other programs or into the Windows sign-in process ({e.Name}).");
        // 6
        if (e.Kind == EntryKind.ComHijack)
            return ("COM_HIJACK", Severity.High, $"A per-user registration overrides the Windows one for {e.Name}, so Windows loads this file instead.");
        // 7 (-nop / -w hidden alone are common in PC makers' own tasks: unusual, not alarming)
        if (Suspicious(e.Command, e.ScriptText, path) is { } what)
            return ("SUSPICIOUS_COMMAND", IsWeakPattern(what) ? Severity.Medium : Severity.High,
                $"The command contains {what}, which is often used to hide what a program does.");
        // 8
        // A registry-only task with nothing to run is a leftover Windows/uninstall removed (AitAgent, old appraiser tasks...),
        // not the hidden-task trick, which keeps a working action. Seen 37 times on a clean Windows 11 25H2 PC.
        if (e.Kind == EntryKind.Task && e.TaskHidden && e.NoFile && string.IsNullOrWhiteSpace(e.Command))
            return ("TASK_LEFTOVER", Severity.Info, "Leftover scheduled-task entry with nothing to run (its task was removed). Harmless.");
        if (e.Kind == EntryKind.Task && e.TaskHidden)
            return ("TASK_HIDDEN", Severity.High, "This scheduled task is hidden from Task Scheduler (its task file or its security information is missing).");
        // 9
        if (unsigned && RiskyFolder(path) is { } place)
            return ("UNSIGNED_RISKY_PATH", Severity.High, $"{Unsigned(sig)} and runs from {place}.");
        if (unsigned && UserWritable(path) is { } writable && IsRandomLooking(Path.GetFileNameWithoutExtension(file)))
            return ("UNSIGNED_RISKY_PATH", Severity.High, $"{Unsigned(sig)}, runs from {writable} and has a random-looking name.");
        // 10
        if (unsigned && UserWritable(path) is { } folder)
            return ("UNSIGNED_APPDATA", Severity.Medium, $"{Unsigned(sig)} and runs from {folder}.");
        // 11
        if (e.Kind == EntryKind.Service && i.Command.UnquotedPath)
            return ("UNQUOTED_SERVICE_PATH", Severity.Medium, "The service's program path has spaces but no quotes, so Windows could start a different program.");
        // 12
        if (unsigned)
            return ("UNSIGNED", Severity.Medium, $"{Unsigned(sig)}.");
        // 13
        if (sig.Status == SignatureStatus.FileMissing)
            return ("FILE_MISSING", Severity.Low, "The program it points to is missing, probably left over from something that was uninstalled.");
        // 12a: an extension a PROGRAM added from outside the browser's own store (classic home-PC browser hijacker).
        // Policy-forced extensions are judged by the posture check "Forced browser extensions", so they are not counted twice.
        if (e.Kind == EntryKind.BrowserExtension && !e.Location.Contains(@"\Policies\", StringComparison.OrdinalIgnoreCase) && OffStoreUrl(e.Command) is { } host)
            return ("EXTENSION_OFF_STORE", Severity.Medium, $"This browser extension is installed from {host}, not from the browser's own web store. Browser hijackers are installed this way.");
        // 13a: signed adware and browser hijackers (the unsigned rules never catch them)
        if (valid && Signing.SignerNames.UnwantedPublisher(sig.Signer) is { } publisher)
            return ("UNWANTED_PUBLISHER", Severity.Medium, $"Signed by {signer}. {publisher} is known for unwanted programs (browser hijackers, adware, fake optimizers). If you did not choose to install it, uninstall it and do not move it to the new PC.");
        // 13b: another company's driver signed through Microsoft's hardware program: not Microsoft's own code
        if (valid && Signing.SignerNames.IsWhql(sig.Signer))
            return ("WHQL_DRIVER", Severity.Info, "A driver made by another company and approved through Microsoft's driver program.");
        // 13c: a Microsoft program used to start something from a user folder or the internet (it would otherwise be hidden)
        if (valid && sig.IsMicrosoft && LaunchTarget(i.Command.Arguments) is { } launched)
            return ("LAUNCHER_ARGS", Severity.Medium, $"A Windows program is used to start {launched}. Malware does this to hide behind a trusted name.");
        // 14
        if (valid && !sig.IsMicrosoft && IsOemKnown(sig.Signer, path))
            return ("OEM_KNOWN", Severity.Info, $"Signed by {signer}, a known PC or hardware maker.");
        // 15
        if (valid && !sig.IsMicrosoft)
            return ("SIGNED_THIRD_PARTY", Severity.Info, $"Signed by {signer}.");
        // 16
        if (valid && sig.IsMicrosoft)
            return ("MICROSOFT", Severity.Hidden, "Part of Windows or signed by Microsoft.");
        // 17
        if (e.NoFile || e.Kind == EntryKind.BrowserExtension)
            return ("NOT_VERIFIABLE", Severity.Info, "There is no program file to check.");
        if (i.Command.PayloadIsUrl)
            return ("NOT_VERIFIABLE", Severity.Info, "It runs something from the internet, which cannot be checked here.");
        return ("NOT_VERIFIABLE", Severity.Info, "The signature could not be checked.");
    }

    static string Unsigned(SignatureInfo sig) => sig.Status == SignatureStatus.Invalid
        ? "The program's digital signature is broken" : "The program has no digital signature (the stamp that proves who made it)";

    /// <summary>Returns a plain description of the first suspicious pattern found in the command, script text or payload path.</summary>
    public static string? Suspicious(string? command, string? scriptText, string? normalizedPayload)
    {
        foreach (var text in new[] { command, scriptText })
        {
            if (string.IsNullOrEmpty(text)) continue;
            for (int k = 0; k < SuspiciousRegexes.Length; k++)
            {
                try { if (SuspiciousRegexes[k].IsMatch(text)) return SuspiciousPatterns[k].What; }
                catch (RegexMatchTimeoutException) { return "an unusually complex command"; }
            }
        }
        var p = NormalizePath(normalizedPayload);
        if (p.Length > 0 && InAppData(p) && ScriptExtensions.Any(x => p.EndsWith(x, StringComparison.Ordinal)))
            return "a script file in the AppData folder";
        return null;
    }

    /// <summary>Lower-case, backslashes, user env vars turned into the folders they stand for.</summary>
    public static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        var p = path.Trim().Trim('"').Replace('/', '\\').ToLowerInvariant();
        p = p.Replace("%localappdata%", @"\appdata\local").Replace("%appdata%", @"\appdata\roaming")
             .Replace("%temp%", @"\temp").Replace("%tmp%", @"\temp").Replace("%public%", @"\users\public")
             .Replace("%userprofile%", @"\users\%user%");
        return p;
    }

    static string FileName(string normalized)
    {
        var i = normalized.LastIndexOf('\\');
        return i >= 0 ? normalized[(i + 1)..] : normalized;
    }

    static string? RiskyFolder(string p)
    {
        if (p.Contains(@"\temp\") || p.Contains(@"\tmp\")) return "a Temp folder";
        if (p.Contains(@"\downloads\")) return "a Downloads folder";
        if (p.Contains(@"\users\public\")) return @"the shared Users\Public folder";
        return null;
    }

    static bool InAppData(string p) => p.Contains(@"\appdata\");

    /// <summary>AppData, or ProgramData outside Microsoft's own folder (miners and remote-access tools drop there).</summary>
    static string? UserWritable(string p) =>
        InAppData(p) ? "the AppData folder"
        : p.Contains(@"\programdata\") && !p.Contains(@"\programdata\microsoft\") ? "the ProgramData folder"
        : null;

    static readonly string[] StoreHosts = ["clients2.google.com", "edge.microsoft.com", "addons.mozilla.org"];

    /// <summary>The host of a web address in an extension entry that is not a browser store, or null.</summary>
    public static string? OffStoreUrl(string? command)
    {
        var m = Regex.Match(command ?? "", @"https?://([^/\s;""]+)", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        var host = m.Groups[1].Value.ToLowerInvariant();
        return StoreHosts.Any(s => host == s || host.EndsWith("." + s, StringComparison.Ordinal)) ? null : host;
    }

    static bool IsWeakPattern(string what) => what is "a hidden window switch (-w hidden)" or "the -nop switch";

    /// <summary>What a trusted program's arguments start from a user folder or the internet ("a file in the AppData folder"), or null.</summary>
    public static string? LaunchTarget(string? arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments)) return null;
        if (arguments.Contains("http://", StringComparison.OrdinalIgnoreCase) || arguments.Contains("https://", StringComparison.OrdinalIgnoreCase))
            return "something from the internet";
        var a = NormalizePath(arguments);
        if (RiskyFolder(a + "\\") is { } risky) return "a file in " + risky;
        if (UserWritable(a) is { } writable) return "a file in " + writable;
        return null;
    }

    /// <summary>Hex strings, GUIDs, or consonant soup with digits ("x7kq9zt2.exe").</summary>
    public static bool IsRandomLooking(string? stem)
    {
        if (string.IsNullOrEmpty(stem)) return false;
        var s = stem.Trim('{', '}').ToLowerInvariant();
        if (Guid.TryParse(s, out _)) return true;
        if (s.Length >= 8 && s.All(Uri.IsHexDigit) && s.Any(char.IsDigit) && s.Any(char.IsLetter)) return true;
        if (s.Length < 8 || !s.All(char.IsAsciiLetterOrDigit)) return false;
        int digits = s.Count(char.IsDigit), letters = s.Count(char.IsLetter), vowels = s.Count(c => "aeiou".Contains(c));
        return digits >= 2 && letters >= 3 && vowels * 5 < letters;
    }

    public static bool IsOemKnown(string? signer, string? payloadPath)
    {
        if (string.IsNullOrWhiteSpace(signer)) return false;
        var p = NormalizePath(payloadPath);
        if (p.Length > 2 && p[1] == ':') p = p[2..];
        foreach (var (signers, prefixes) in OemAllowlist)
            if (signers.Any(s => signer.Contains(s, StringComparison.OrdinalIgnoreCase)) && prefixes.Any(x => p.StartsWith(x, StringComparison.Ordinal)))
                return true;
        return false;
    }

    // ---- Windows defaults (used by the location readers so default values produce no finding) ----

    public static bool IsDefaultShell(string? value)
    {
        var v = (value ?? "").Trim().Trim(',').Trim().ToLowerInvariant();
        return v is "explorer.exe" or "explorer" or @"%systemroot%\explorer.exe" or @"%windir%\explorer.exe" or @"c:\windows\explorer.exe";
    }

    public static bool IsDefaultUserinitPart(string part)
    {
        var v = part.Trim().Trim('"').ToLowerInvariant();
        if (v.Length == 0 || v is "userinit.exe" or "userinit" or @"system32\userinit.exe") return true;
        const string tail = @"\windows\system32\userinit.exe";
        return v is @"%systemroot%\system32\userinit.exe" or @"%windir%\system32\userinit.exe"
            || (v.Length == 2 + tail.Length && v[1] == ':' && v.EndsWith(tail, StringComparison.Ordinal));
    }

    public static bool IsDefaultBootExecute(string entry) =>
        string.Join(' ', entry.Trim().ToLowerInvariant().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) == "autocheck autochk *";

    static readonly Dictionary<string, string[]> KnownLsa = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Authentication Packages"] = ["msv1_0"],
        ["Security Packages"] = ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp", "\"\""],
        ["Notification Packages"] = ["scecli", "rassfm"],
    };

    public static bool IsKnownLsaPackage(string list, string package)
    {
        var p = package.Trim();
        if (p.Length == 0 || p == "\"\"") return true;
        if (p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) p = p[..^4];
        return KnownLsa.TryGetValue(list, out var known) && known.Contains(p, StringComparer.OrdinalIgnoreCase);
    }
}
