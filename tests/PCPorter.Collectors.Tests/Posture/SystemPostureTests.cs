using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Posture;

public class SystemPostureTests
{
    // ---- 3. Windows Update ----
    static FakeWmiClient Qfe(params string?[] dates) =>
        new FakeWmiClient().Add(@"root\cimv2", "Win32_QuickFixEngineering", dates.Select(d => PT.Row(("HotFixID", "KB1"), ("InstalledOn", d))).ToArray());

    [Theory]
    [InlineData("11/10/2026", PostureStatus.Good)]
    [InlineData("10/1/2026", PostureStatus.Attention)]
    [InlineData("8/1/2026", PostureStatus.Risk)]
    [InlineData("20261120", PostureStatus.Good)]
    public void Update_recency_live(string newest, PostureStatus expected)
    {
        var c = PT.Check(PT.Live(), PostureIds.WindowsUpdate, Qfe("1/2/2020", newest, null, "garbage"));
        Assert.Equal(expected, c.Status);
    }

    [Fact]
    public void Update_recency_unknown_when_no_dates()
    {
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Live(), PostureIds.WindowsUpdate, Qfe("garbage")).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.WindowsUpdate).Status);
    }

    [Fact]
    public void InstalledOn_formats_are_culture_invariant()
    {
        Assert.Equal(new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero), SystemChecks.ParseInstalledOn("3/4/2026"));
        Assert.Equal(new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero), SystemChecks.ParseInstalledOn("20260304"));
        var ft = new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero).ToFileTime().ToString("x16");
        Assert.Equal(new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero), SystemChecks.ParseInstalledOn(ft));
        Assert.Null(SystemChecks.ParseInstalledOn("not a date"));
        Assert.Null(SystemChecks.ParseInstalledOn(""));
    }

    [Fact]
    public void Update_recency_offline_uses_newest_package_key()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages", k => k.Key("PkgOld").Key("PkgNew"));
        DateTimeOffset? Lw(string name) => name switch { "PkgOld" => PT.Now.AddDays(-200), "PkgNew" => PT.Now.AddDays(-60), _ => null };
        var reads = new List<string>();
        var c = PT.Check(new SpySource(PT.Offline(sw), reads, Lw), PostureIds.WindowsUpdate);
        Assert.Equal(PostureStatus.Attention, c.Status);
        Assert.Contains("approximation", c.Evidence);
        Assert.Contains("2 Component Based Servicing", c.Evidence);
    }

    // ---- 5. Firewall ----
    static RegSpec Fw(uint domain, uint std, uint pub) => PT.System(c => c
        .Key(@"Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", k => k.Num("EnableFirewall", domain))
        .Key(@"Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", k => k.Num("EnableFirewall", std))
        .Key(@"Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", k => k.Num("EnableFirewall", pub)));

    [Fact]
    public void Firewall_profiles()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: Fw(1, 1, 1)), PostureIds.Firewall).Status);
        Assert.Equal(PostureStatus.Risk, PT.Check(PT.Offline(system: Fw(1, 0, 1)), PostureIds.Firewall).Status);
        Assert.Equal(PostureStatus.Risk, PT.Check(PT.Offline(system: Fw(1, 1, 0)), PostureIds.Firewall).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(system: Fw(0, 1, 1)), PostureIds.Firewall).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(system: PT.System()), PostureIds.Firewall).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.Firewall).Status);
    }

    [Fact]
    public void Firewall_policy_overrides_local_setting()
    {
        var policyOff = RegSpec.Root().Key(@"Policies\Microsoft\WindowsFirewall\PublicProfile", k => k.Num("EnableFirewall", 0));
        var c = PT.Check(PT.Offline(policyOff, Fw(1, 1, 1)), PostureIds.Firewall);
        Assert.Equal(PostureStatus.Risk, c.Status);
        Assert.Contains("public network", c.Finding);

        var policyOn = RegSpec.Root().Key(@"Policies\Microsoft\WindowsFirewall\PrivateProfile", k => k.Num("EnableFirewall", 1));
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(policyOn, Fw(1, 0, 1)), PostureIds.Firewall).Status);
    }

    // ---- 11. SMB1 ----
    [Fact]
    public void Smb1()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: PT.System(c => c.Key(@"Services\LanmanServer\Parameters"))), PostureIds.Smb1).Status);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: PT.System(c => c.Key(@"Services\mrxsmb10", k => k.Num("Start", 4)))), PostureIds.Smb1).Status);
        Assert.Equal(PostureStatus.Risk, PT.Check(PT.Offline(system: PT.System(c => c.Key(@"Services\mrxsmb10", k => k.Num("Start", 2)))), PostureIds.Smb1).Status);
        Assert.Equal(PostureStatus.Risk, PT.Check(PT.Offline(system: PT.System(c => c.Key(@"Services\LanmanServer\Parameters", k => k.Num("SMB1", 1)))), PostureIds.Smb1).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.Smb1).Status);
    }

    // ---- 12. Remote Desktop ----
    static RegSpec Rdp(uint deny, uint? nla = null, uint? port = null) => PT.System(c => c
        .Key(@"Control\Terminal Server", k => k.Num("fDenyTSConnections", deny))
        .Key(@"Control\Terminal Server\WinStations\RDP-Tcp", k => { if (nla is { } n) k.Num("UserAuthentication", n); if (port is { } p) k.Num("PortNumber", p); }));

    [Fact]
    public void Remote_desktop()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: Rdp(1)), PostureIds.RemoteDesktop).Status);
        var withNla = PT.Check(PT.Offline(system: Rdp(0, 1, 3389)), PostureIds.RemoteDesktop);
        Assert.Equal(PostureStatus.Attention, withNla.Status);
        var noNla = PT.Check(PT.Offline(system: Rdp(0, 0, 3390)), PostureIds.RemoteDesktop);
        Assert.Equal(PostureStatus.Risk, noNla.Status);
        Assert.Contains("3390", noNla.Finding);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(system: PT.System()), PostureIds.RemoteDesktop).Status);
    }

    // ---- 13. UAC ----
    static RegSpec Uac(uint? lua, uint? consent) => RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\Policies\System", k =>
    {
        if (lua is { } l) k.Num("EnableLUA", l);
        if (consent is { } c) k.Num("ConsentPromptBehaviorAdmin", c);
    });

    [Fact]
    public void Uac_levels()
    {
        var off = PT.Check(PT.Offline(Uac(0, 5)), PostureIds.Uac);
        Assert.Equal((PostureStatus.Risk, PostureSeverity.Critical), (off.Status, off.Severity));
        var silent = PT.Check(PT.Offline(Uac(1, 0)), PostureIds.Uac);
        Assert.Equal((PostureStatus.Risk, PostureSeverity.High), (silent.Status, silent.Severity));
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(Uac(1, 5)), PostureIds.Uac).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(Uac(null, 5)), PostureIds.Uac).Status);
    }

    // ---- 15. Memory integrity, LSA, Smart App Control ----
    [Fact]
    public void Hardening_settings()
    {
        var on = PT.System(c => c
            .Key(@"Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", k => k.Num("Enabled", 1))
            .Key(@"Control\Lsa", k => k.Num("RunAsPPL", 2))
            .Key(@"Control\CI\Policy", k => k.Num("VerifiedAndReputablePolicyState", 1)));
        var off = PT.System(c => c
            .Key(@"Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", k => k.Num("Enabled", 0))
            .Key(@"Control\Lsa", k => k.Num("RunAsPPL", 0))
            .Key(@"Control\CI\Policy", k => k.Num("VerifiedAndReputablePolicyState", 0)));
        var checksOn = PT.Run(PT.Offline(system: on)).Checks;
        var checksOff = PT.Run(PT.Offline(system: off)).Checks;
        foreach (var id in new[] { PostureIds.MemoryIntegrity, PostureIds.LsaProtection, PostureIds.SmartAppControl })
        {
            Assert.Equal(PostureStatus.Good, checksOn.Single(c => c.Id == id).Status);
            var o = checksOff.Single(c => c.Id == id);
            Assert.Equal(PostureStatus.Attention, o.Status);
            Assert.True(o.Severity <= PostureSeverity.Low);
        }
        var eval = PT.System(c => c.Key(@"Control\CI\Policy", k => k.Num("VerifiedAndReputablePolicyState", 2)));
        Assert.Contains("evaluation", PT.Check(PT.Offline(system: eval), PostureIds.SmartAppControl).Finding);
        var empty = PT.Run(PT.Offline(system: PT.System())).Checks;
        Assert.Equal(PostureStatus.Unknown, empty.Single(c => c.Id == PostureIds.MemoryIntegrity).Status);
        Assert.Equal(PostureStatus.Unknown, empty.Single(c => c.Id == PostureIds.LsaProtection).Status);
    }

    [Fact]
    public void Smart_app_control_not_applicable_on_windows_10()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Str("CurrentBuild", "19045"));
        Assert.Equal(PostureStatus.NotApplicable, PT.Check(PT.Offline(sw, PT.System()), PostureIds.SmartAppControl).Status);
    }

    // ---- 16. Pending reboot ----
    [Fact]
    public void Pending_reboot()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(RegSpec.Root(), PT.System()), PostureIds.PendingReboot).Status);
        var cbs = RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
        var c = PT.Check(PT.Offline(cbs, PT.System()), PostureIds.PendingReboot);
        Assert.Equal((PostureStatus.Attention, PostureSeverity.Low), (c.Status, c.Severity));
        var wu = RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(wu, PT.System()), PostureIds.PendingReboot).Status);
        var rename = PT.System(s => s.Key(@"Control\Session Manager", k => k.Multi("PendingFileRenameOperations", @"\??\C:\a.tmp", "")));
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(RegSpec.Root(), rename), PostureIds.PendingReboot).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.PendingReboot).Status);
    }

    // ---- 17. Disk space ----
    [Fact]
    public void Disk_space_offline_and_live()
    {
        var opts = (Func<string, (long, long)?> f) => new PostureOptions(Now: PT.Now, Listeners: () => [], DriveSpace: f);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(), PostureIds.DiskSpace, options: opts(_ => (20, 100))).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(), PostureIds.DiskSpace, options: opts(_ => (9, 100))).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.DiskSpace, options: opts(_ => null)).Status);

        var wmi = new FakeWmiClient().Add(@"root\cimv2", "Win32_LogicalDisk",
            PT.Row(("DeviceID", "C:"), ("FreeSpace", 50UL * 1024 * 1024 * 1024), ("Size", 500UL * 1024 * 1024 * 1024)),
            PT.Row(("DeviceID", "D:"), ("FreeSpace", 1UL * 1024 * 1024 * 1024), ("Size", 100UL * 1024 * 1024 * 1024)));
        var live = PT.Check(PT.Live(), PostureIds.DiskSpace, wmi, new PostureOptions(Now: PT.Now, Listeners: () => []));
        Assert.Equal(PostureStatus.Attention, live.Status);
        Assert.Contains("D:", live.Finding);
        Assert.DoesNotContain("C:", live.Finding);
    }

    // ---- 14. Listening ports ----
    [Fact]
    public void Listening_ports_live_only_and_risky_only_on_all_interfaces()
    {
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.ListeningPorts).Status);
        Assert.True(PT.Check(PT.Offline(), PostureIds.ListeningPorts).LiveOnly);

        PostureOptions With(params PortListener[] l) => new(Now: PT.Now, Listeners: () => l, DriveSpace: _ => (50, 100));
        var safe = PT.Check(PT.Live(), PostureIds.ListeningPorts, options: With(new("127.0.0.1", 3389, 10, "x"), new("0.0.0.0", 8080, 11, "y")));
        Assert.Equal(PostureStatus.Good, safe.Status);
        Assert.Contains("0.0.0.0:8080", safe.Evidence);
        var risky = PT.Check(PT.Live(), PostureIds.ListeningPorts, options: With(new("::", 445, 4, "System"), new("0.0.0.0", 5900, 12, null)));
        Assert.Equal(PostureStatus.Attention, risky.Status);
        Assert.Contains("445", risky.Finding);
        Assert.Contains("5900", risky.Finding);
    }

    // ---- Robustness ----
    [Fact]
    public void Empty_pc_gives_every_check_and_never_throws()
    {
        var (checks, output, _) = PT.Run(PT.Offline());
        Assert.Equal(SecurityPostureCollector.Kind, output.Kind);
        Assert.NotEqual(CollectorStatus.Failed, output.Status);
        foreach (var id in typeof(PostureIds).GetFields().Where(f => f.Name != nameof(PostureIds.BrowserExtensionPrefix)).Select(f => (string)f.GetValue(null)!))
            Assert.Single(checks, c => c.Id == id);
        Assert.All(checks, c => Assert.Equal(c.Id, c.ItemKey));
        Assert.All(checks.Where(c => c.Status != PostureStatus.Good), c => Assert.False(string.IsNullOrWhiteSpace(c.Advice)));
    }

    [Fact]
    public void Wrong_value_types_do_not_throw()
    {
        var sw = RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Bin("CurrentBuild", 1, 2, 3).Bin("EditionID", 9))
            .Key(@"Microsoft\Windows NT\CurrentVersion\Winlogon", k => k.Bin("AutoAdminLogon", 1))
            .Key(@"Microsoft\Windows\CurrentVersion\Policies\System", k => k.Str("EnableLUA", "yes"));
        var sys = PT.System(c => c.Key(@"Control\Session Manager", k => k.Num("PendingFileRenameOperations", 3))
            .Key(@"Services\Tcpip\Parameters", k => k.Num("NameServer", 1).Num("DataBasePath", 2)));
        var (checks, output, warnings) = PT.Run(PT.Offline(sw, sys));
        Assert.Equal(CollectorStatus.Ok, output.Status);
        Assert.Empty(warnings);
        Assert.Equal(PostureStatus.Unknown, checks.Single(c => c.Id == PostureIds.WindowsSupport).Status);
        Assert.Equal(PostureStatus.Unknown, checks.Single(c => c.Id == PostureIds.Uac).Status);
    }
}
