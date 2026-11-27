using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;
using Xunit.Abstractions;

namespace PCPorter.Collectors.Tests.Persistence;

public class PersistenceCollectorTests(ITestOutputHelper output) : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-pc").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    const string CV = @"Microsoft\Windows\CurrentVersion";

    /// <summary>A mini Windows drive with REAL hive files written by offreg.dll.</summary>
    void MiniWindows()
    {
        var config = Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "config")).FullName;
        Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "Tasks"));
        File.WriteAllText(Path.Combine(_root, "Windows", "System32", "svchost.exe"), "MZ");
        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Str("SystemRoot", @"C:\Windows"))
            .Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList\" + P.BobSid, k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob"))
            .Key(@"Microsoft\Windows NT\CurrentVersion\Winlogon", k => k.Str("Shell", "explorer.exe").Str("Userinit", @"C:\Windows\system32\userinit.exe,"))
            .Key(CV + @"\Run", k => k.Str("", @"C:\Users\Public\evil.exe").Str("Audio", @"""C:\Program Files\Realtek\rt.exe"" -s"))
            .Key(CV + @"\Explorer\StartupApproved\Run", k => k.Bin("Audio", 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
            Path.Combine(config, "SOFTWARE"));
        OffregHiveBuilder.Save(RegSpec.Root().Key("Select", k => k.Num("Current", 1))
            .Key(@"ControlSet001\Services\Evil", k => k.Num("Start", 2).Exp("ImagePath", @"%SystemRoot%\system32\svchost.exe -k netsvcs")
                .Key("Parameters", p => p.Exp("ServiceDll", @"%SystemRoot%\System32\evil.dll")))
            .Key(@"ControlSet001\Control\Session Manager", k => k.Multi("BootExecute", "autocheck autochk *")),
            Path.Combine(config, "SYSTEM"));
        var bob = Directory.CreateDirectory(Path.Combine(_root, "Users", "bob")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root().Key(@"Software\" + CV + @"\Run", k => k.Str("Helper", @"%LOCALAPPDATA%\Helper\helper.exe")),
            Path.Combine(bob, "NTUSER.DAT"));
        P.WriteTask(Path.Combine(_root, @"Windows\System32\Tasks"), @"\Microsoft\Windows\Sneaky", P.Exec(@"C:\Users\Public\s.exe"));
    }

    [Fact]
    public void Offline_drive_with_offreg_built_hives()
    {
        MiniWindows();
        using var src = new OfflineSource(_root, runningWindowsDrive: @"Z:\");
        var ctx = P.Context(src);
        var o = new PersistenceCollector().Run(ctx, CancellationToken.None);
        Assert.Equal("persistence", o.Kind);
        var items = P.Items(o);

        var def = Assert.Single(items, i => i.Name == "(Default)");
        Assert.Equal(SignatureStatus.FileMissing, def.SignatureStatus);
        var audio = Assert.Single(items, i => i.Name == "Audio");
        Assert.True(audio.Disabled);
        var helper = Assert.Single(items, i => i.Name == "Helper");
        Assert.Equal(@"HKCU(bob)\Software\Microsoft\Windows\CurrentVersion\Run", helper.Location);
        Assert.Equal(@"C:\Users\bob\AppData\Local\Helper\helper.exe", helper.PayloadPath);
        var svc = Assert.Single(items, i => i.Name == "Evil");
        Assert.Equal(@"C:\Windows\System32\evil.dll", svc.PayloadPath);
        Assert.Single(items, i => i.Name == "Sneaky");
        Assert.DoesNotContain(items, i => i.RuleId == "WINLOGON_CHANGED");
        Assert.Contains(o.Notes, n => n.Contains("autostart entries"));
        Assert.Equal(items.Count, items.Select(i => i.ItemKey).Distinct().Count());
    }

    [Fact]
    public void Signature_check_gets_mapped_paths_only()
    {
        MiniWindows();
        using var src = new OfflineSource(_root, runningWindowsDrive: @"Z:\");
        var sigs = new FakeSignatures(_ => FakeSignatures.Unsigned);
        new PersistenceCollector().Run(P.Context(src, sigs), CancellationToken.None);
        Assert.NotEmpty(sigs.Checked);
        Assert.All(sigs.Checked, p => Assert.StartsWith(_root, p, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Throwing_signature_checker_becomes_a_warning()
    {
        MiniWindows();
        using var src = new OfflineSource(_root, runningWindowsDrive: @"Z:\");
        var ctx = P.Context(src, new FakeSignatures(_ => throw new InvalidOperationException("boom")));
        var o = new PersistenceCollector().Run(ctx, CancellationToken.None);
        Assert.NotEmpty(o.Items);
        Assert.Contains(ctx.Warnings, w => w.Contains("boom"));
        Assert.All(P.Items(o), i => Assert.Equal(SignatureStatus.NotChecked, i.SignatureStatus));
    }

    [Fact]
    public void Cancelled_run_returns_cancelled_status()
    {
        MiniWindows();
        using var src = new OfflineSource(_root, runningWindowsDrive: @"Z:\");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var o = new PersistenceCollector().Run(P.Context(src), cts.Token);
        Assert.Equal(CollectorStatus.Cancelled, o.Status);
    }

    [Fact]
    [Trait("Category", "Live")]
    public void Live_non_admin_scan_runs_without_exceptions()
    {
        using var src = new LiveSource();
        var ctx = new CollectorContext(src, new WmiClient(), new ProcessRunner(), new NoSignatureChecker(), Path.GetTempPath(), new List<string>());
        var o = new PersistenceCollector().Run(ctx, CancellationToken.None);
        Assert.Equal("persistence", o.Kind);
        Assert.NotEmpty(o.Items);
        var items = P.Items(o);
        // Counts only: no names or paths from this PC go into the test output.
        foreach (var s in Enum.GetValues<Severity>().Reverse())
            output.WriteLine($"{s}: {items.Count(i => i.Severity == s)}");
        output.WriteLine($"Total: {items.Count}; warnings: {ctx.Warnings.Count}; status: {o.Status}");
    }
}
