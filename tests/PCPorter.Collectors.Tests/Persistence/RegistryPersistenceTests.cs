using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Persistence;

public class RegistryPersistenceTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-regp").FullName;
    public void Dispose() => Directory.Delete(_root, true);

    const string CV = @"Microsoft\Windows\CurrentVersion";
    const string NT = @"Microsoft\Windows NT\CurrentVersion";

    UserProfile Bob => new(P.BobSid, "bob", Path.Combine(_root, "Users", "bob"), null);

    FakeSystemSource Source(RegSpec? software = null, RegSpec? system = null, RegSpec? ntuser = null, RegSpec? usrClass = null)
    {
        var hives = new Dictionary<string, RegSpec>();
        if (ntuser is not null) hives[P.BobSid] = ntuser;
        if (usrClass is not null) hives[P.BobSid + "_Classes"] = usrClass;
        return new FakeSystemSource(_root, software ?? RegSpec.Root(), system ?? RegSpec.Root().Key("Select", k => k.Num("Current", 1)), hives, [Bob]);
    }

    static List<PersistenceEntry> Read(ISystemSource s, List<string>? warnings = null) => RegistryPersistence.Read(s, warnings ?? []).ToList();

    [Fact]
    public void Null_named_and_nul_prefixed_run_values_are_found()
    {
        var sw = RegSpec.Root().Key(CV + @"\Run", k => k.Str("", @"C:\Users\Public\evil.exe").Str("\0hidden", @"C:\x\y.exe").Str("OneDrive", @"""C:\od\OneDrive.exe"" /background"));
        var entries = Read(Source(software: sw));
        var def = Assert.Single(entries, e => e.Name == "(Default)");
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", def.Location);
        Assert.Equal(@"C:\Users\Public\evil.exe", def.Command);
        Assert.Single(entries, e => e.Name == "\\0hidden");
        Assert.Single(entries, e => e.Name == "OneDrive");
    }

    [Fact]
    public void All_run_family_keys_machine_wow_and_user()
    {
        var sw = RegSpec.Root()
            .Key(CV + @"\RunOnce", k => k.Str("a", @"C:\a.exe"))
            .Key(CV + @"\RunServices", k => k.Str("b", @"C:\b.exe"))
            .Key(CV + @"\Policies\Explorer\Run", k => k.Str("c", @"C:\c.exe"))
            .Key(CV + @"\RunOnceEx\0001", k => k.Str("Title", "x").Str("1", @"||C:\d.dll|Entry"))
            .Key(@"WOW6432Node\" + CV + @"\Run", k => k.Str("e", @"C:\e.exe"));
        var nt = RegSpec.Root().Key(@"Software\" + CV + @"\Run", k => k.Str("f", @"%APPDATA%\f.exe"));
        var entries = Read(Source(software: sw, ntuser: nt));
        Assert.Equal(["a", "b", "c", "e"], entries.Where(e => e.Location.StartsWith("HKLM") && !e.Location.Contains("RunOnceEx")).Select(e => e.Name).Order());
        Assert.Equal(@"C:\d.dll", Assert.Single(entries, e => e.Location.Contains("RunOnceEx")).Command);
        var f = Assert.Single(entries, e => e.Name == "f");
        Assert.Equal(@"HKCU(bob)\Software\Microsoft\Windows\CurrentVersion\Run", f.Location);
        Assert.Equal("bob", f.User?.UserName);
        // %APPDATA% expands with the user's own profile.
        var item = PersistenceCollector.Evaluate(f, Source(), new NoSignatureChecker());
        Assert.Equal(@"C:\Users\bob\AppData\Roaming\f.exe", item.PayloadPath);
    }

    [Fact]
    public void Shadowing_hkcu_clsid_is_a_com_hijack()
    {
        const string shadowed = "{11111111-2222-3333-4444-555555555555}";
        const string userOnly = "{99999999-2222-3333-4444-555555555555}";
        const string viaUsrClass = "{AAAAAAAA-2222-3333-4444-555555555555}";
        var sw = RegSpec.Root()
            .Key($@"Classes\CLSID\{shadowed}\InprocServer32", k => k.Exp("", @"%SystemRoot%\System32\shell32.dll"))
            .Key($@"WOW6432Node\Classes\CLSID\{viaUsrClass}\LocalServer32", k => k.Str("", @"C:\Windows\SysWOW64\x.exe"));
        var nt = RegSpec.Root()
            .Key($@"Software\Classes\CLSID\{shadowed}\InprocServer32", k => k.Str("", @"C:\Users\bob\AppData\Roaming\evil.dll"))
            .Key($@"Software\Classes\CLSID\{userOnly}\InprocServer32", k => k.Str("", @"C:\Users\bob\AppData\Local\App\app.dll"));
        var cls = RegSpec.Root().Key($@"CLSID\{viaUsrClass}\LocalServer32", k => k.Str("", @"C:\Users\bob\AppData\Local\evil.exe"));
        var entries = Read(Source(software: sw, ntuser: nt, usrClass: cls)).Where(e => e.Kind == EntryKind.ComHijack).ToList();
        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Name == shadowed + @"\InprocServer32" && e.Command.EndsWith("evil.dll"));
        Assert.Contains(entries, e => e.Name == viaUsrClass + @"\LocalServer32");
        var item = PersistenceCollector.Evaluate(entries[0], Source(), new NoSignatureChecker());
        Assert.Equal("COM_HIJACK", item.RuleId);
        Assert.Equal(Severity.High, item.Severity);
    }

    [Fact]
    public void StartupApproved_odd_first_byte_disables_and_downgrades()
    {
        var nt = RegSpec.Root()
            .Key(@"Software\" + CV + @"\Run", k => k.Str("Off", @"C:\Users\Public\off.exe").Str("On", @"C:\Users\Public\on.exe"))
            .Key(@"Software\" + CV + @"\Explorer\StartupApproved\Run", k => k
                .Bin("Off", 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                .Bin("On", 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        var sw = RegSpec.Root()
            .Key(@"WOW6432Node\" + CV + @"\Run", k => k.Str("Old32", @"C:\old.exe"))
            .Key(CV + @"\Explorer\StartupApproved\Run32", k => k.Bin("Old32", 0x01, 0, 0, 0));
        var src = Source(software: sw, ntuser: nt);
        var entries = Read(src);
        Assert.True(entries.Single(e => e.Name == "Off").Disabled);
        Assert.False(entries.Single(e => e.Name == "On").Disabled);
        Assert.True(entries.Single(e => e.Name == "Old32").Disabled);

        var sigs = new FakeSignatures(_ => FakeSignatures.Unsigned);
        var off = PersistenceCollector.Evaluate(entries.Single(e => e.Name == "Off"), src, sigs);
        var on = PersistenceCollector.Evaluate(entries.Single(e => e.Name == "On"), src, sigs);
        Assert.Equal(Severity.High, on.Severity);
        Assert.Equal(Severity.Medium, off.Severity);
        Assert.True(off.Disabled);
    }

    [Fact]
    public void Svchost_service_is_scored_on_its_ServiceDll()
    {
        var sys = RegSpec.Root().Key("Select", k => k.Num("Current", 1))
            .Key(@"ControlSet001\Services\EvilSvc", k => k.Num("Start", 2).Exp("ImagePath", @"%SystemRoot%\system32\svchost.exe -k netsvcs -p")
                .Key("Parameters", p => p.Exp("ServiceDll", @"C:\Users\Public\evil.dll")))
            .Key(@"ControlSet001\Services\GoodSvc", k => k.Num("Start", 2).Exp("ImagePath", @"%SystemRoot%\system32\svchost.exe -k LocalService")
                .Key("Parameters", p => p.Exp("ServiceDll", @"%SystemRoot%\System32\good.dll")))
            .Key(@"ControlSet001\Services\Manual", k => k.Num("Start", 3).Str("ImagePath", @"C:\Users\Public\manual.exe"))
            .Key(@"ControlSet001\Services\Unquoted", k => k.Num("Start", 2).Str("ImagePath", @"C:\Program Files\Vendor Tool\svc.exe -k"));
        var src = Source(system: sys);
        var entries = Read(src);
        Assert.DoesNotContain(entries, e => e.Name == "Manual");
        var evil = entries.Single(e => e.Name == "EvilSvc");
        Assert.Equal(EntryKind.Service, evil.Kind);
        Assert.Equal(@"HKLM\SYSTEM\CurrentControlSet\Services", evil.Location);

        var sigs = FakeSignatures.WindowsIsMicrosoft();
        var evilItem = PersistenceCollector.Evaluate(evil, src, sigs);
        Assert.Equal(@"C:\Users\Public\evil.dll", evilItem.PayloadPath);
        Assert.Equal("UNSIGNED_RISKY_PATH", evilItem.RuleId);
        Assert.Equal(Severity.High, evilItem.Severity);
        Assert.Equal(@"C:\Windows\system32\svchost.exe", evilItem.ImagePath);
        Assert.Equal("MICROSOFT", PersistenceCollector.Evaluate(entries.Single(e => e.Name == "GoodSvc"), src, sigs).RuleId);

        var unq = PersistenceCollector.Evaluate(entries.Single(e => e.Name == "Unquoted"), src, new FakeSignatures(_ => new SignatureInfo(SignatureStatus.Valid, "Vendor", false)));
        Assert.Equal("UNQUOTED_SERVICE_PATH", unq.RuleId);
    }

    [Fact]
    public void Winlogon_defaults_produce_no_finding_and_DefaultPassword_is_never_read()
    {
        var sw = RegSpec.Root().Key(NT + @"\Winlogon", k => k
            .Str("Shell", "explorer.exe").Str("Userinit", @"C:\Windows\system32\userinit.exe,")
            .Str("DefaultUserName", "bob").Str("DefaultPassword", "hunter2").Str("AutoAdminLogon", "1"));
        var sys = RegSpec.Root().Key("Select", k => k.Num("Current", 1))
            .Key(@"ControlSet001\Control\Session Manager", k => k.Multi("BootExecute", "autocheck autochk *"))
            .Key(@"ControlSet001\Control\Lsa", k => k
                .Multi("Authentication Packages", "msv1_0")
                .Multi("Security Packages", "\"\"")
                .Multi("Notification Packages", "scecli"));
        var nt = RegSpec.Root().Key(@"Software\" + NT + @"\Winlogon", k => k.Str("Shell", "explorer.exe"));
        var reads = new List<string>();
        var src = new RecordingSource(Source(software: sw, system: sys, ntuser: nt), reads);
        var entries = Read(src);
        Assert.DoesNotContain(entries, e => e.Kind is EntryKind.Winlogon or EntryKind.DllInjection);
        Assert.DoesNotContain(reads, r => r.Contains("DefaultPassword", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(reads, r => r == "<enumerate Winlogon>");
    }

    [Fact]
    public void Winlogon_bootexecute_lsa_appinit_ifeo_changes_are_found()
    {
        var sw = RegSpec.Root()
            .Key(NT + @"\Winlogon", k => k.Str("Shell", @"explorer.exe, C:\evil\shell.exe").Str("Userinit", @"C:\Windows\system32\userinit.exe,C:\evil\ui.exe,")
                .Key(@"Notify\bad", n => n.Str("DllName", @"C:\evil\notify.dll")))
            .Key(NT + @"\Windows", k => k.Num("LoadAppInit_DLLs", 1).Str("AppInit_DLLs", @"C:\evil\a.dll,C:\evil\b.dll"))
            .Key(@"WOW6432Node\" + NT + @"\Windows", k => k.Num("LoadAppInit_DLLs", 0).Str("AppInit_DLLs", @"C:\evil\off.dll"))
            .Key(NT + @"\Image File Execution Options\sethc.exe", k => k.Str("Debugger", @"C:\Windows\System32\cmd.exe"))
            .Key(NT + @"\Image File Execution Options\notepad.exe", k => k.Num("GlobalFlag", 0x200))
            .Key(NT + @"\SilentProcessExit\notepad.exe", k => k.Str("MonitorProcess", @"C:\evil\mon.exe"))
            .Key(NT + @"\SilentProcessExit\calc.exe", k => k.Str("MonitorProcess", @"C:\evil\mon2.exe"))
            .Key(CV + @"\Policies\System", k => k.Str("Shell", @"C:\evil\polshell.exe"))
            .Key(@"Microsoft\Active Setup\Installed Components\{X}", k => k.Str("StubPath", @"C:\evil\stub.exe"))
            .Key(@"Microsoft\NetSh", k => k.Str("evilhelper", @"C:\evil\netsh.dll"))
            .Key(@"Policies\Google\Chrome\ExtensionInstallForcelist", k => k.Str("1", "abcdefghijklmnopabcdefghijklmnop;https://clients2.google.com/service/update2/crx"));
        var sys = RegSpec.Root().Key("Select", k => k.Num("Current", 1))
            .Key(@"ControlSet001\Control\Session Manager", k => k.Multi("BootExecute", "autocheck autochk *", "evilnative"))
            .Key(@"ControlSet001\Control\Session Manager\AppCertDlls", k => k.Str("x", @"C:\evil\cert.dll"))
            .Key(@"ControlSet001\Control\Lsa", k => k.Multi("Security Packages", "kerberos", "mimilib"))
            .Key(@"ControlSet001\Control\Print\Monitors\Evil", k => k.Str("Driver", "evilmon.dll"));
        var nt = RegSpec.Root().Key(@"Control Panel\Desktop", k => k.Str("SCRNSAVE.EXE", @"C:\Users\bob\AppData\x.scr"));
        var entries = Read(Source(software: sw, system: sys, ntuser: nt));

        string[] Cmds(EntryKind k) => entries.Where(e => e.Kind == k).Select(e => e.Command).Order().ToArray();
        Assert.Equal([@"C:\evil\notify.dll", @"C:\evil\polshell.exe", @"C:\evil\shell.exe", @"C:\evil\ui.exe", "evilnative"], Cmds(EntryKind.Winlogon));
        Assert.Equal([@"C:\evil\a.dll", @"C:\evil\b.dll", @"C:\evil\cert.dll", "mimilib.dll"], Cmds(EntryKind.DllInjection));
        var ifeo = entries.Where(e => e.Kind == EntryKind.IfeoDebugger).ToList();
        Assert.Equal(3, ifeo.Count);
        Assert.False(ifeo.Single(e => e.Command == @"C:\evil\mon.exe").Disabled);
        Assert.True(ifeo.Single(e => e.Command == @"C:\evil\mon2.exe").Disabled);
        Assert.Contains(entries, e => e.Command == @"C:\evil\stub.exe");
        Assert.Contains(entries, e => e.Command == @"C:\evil\netsh.dll");
        Assert.Contains(entries, e => e.Command == "evilmon.dll" && e.Location.EndsWith(@"Print\Monitors"));
        Assert.Contains(entries, e => e.Name == "SCRNSAVE.EXE");
        var ext = Assert.Single(entries, e => e.Kind == EntryKind.BrowserExtension);
        Assert.Equal("NOT_VERIFIABLE", PersistenceCollector.Evaluate(ext, Source(), new NoSignatureChecker()).RuleId);
    }

    [Fact]
    public void Bad_data_is_a_warning_not_an_exception()
    {
        var warnings = new List<string>();
        var entries = RegistryPersistence.Read(new ThrowingSource(_root), warnings);
        Assert.Empty(entries);
        Assert.NotEmpty(warnings);
    }

    sealed class ThrowingSource(string root) : ISystemSource
    {
        public bool IsLive => false;
        public string ReadRoot => root;
        public string OriginalSystemDrive => "C:";
        public string? MapPath(string p) => null;
        public IRegKey? OpenHive(Hive hive, UserProfile? user = null) => throw new InvalidDataException("corrupt hive");
        public string? CurrentControlSet() => throw new InvalidDataException("corrupt");
        public IReadOnlyList<UserProfile> Users => throw new InvalidDataException("no users");
        public IReadOnlyList<string> Notes => [];
        public void Dispose() { }
    }
}
