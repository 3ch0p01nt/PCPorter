using PCPorter.Collectors.Security;
using PCPorter.Collectors.Sources;
using PCPorter.Collectors.Tests.Health;
using PCPorter.TestKit;
using Xunit.Abstractions;
using static PCPorter.Collectors.Tests.Health.TestContexts;

namespace PCPorter.Collectors.Tests.Security;

public class AvDetectorTests : IDisposable
{
    const string Sc = AvDetector.SecurityCenterNs;
    const string Def = AvDetector.DefenderNs;
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-av").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    static RegSpec SystemWith(params string[] services) => SystemHive(cs => cs.Key("Services", s =>
    {
        foreach (var name in services) s.Key(name, k => k.Num("Start", 2));
    }));

    static List<AvProduct> Run(CollectorContext ctx, out CollectorOutput output)
    {
        output = new AvDetector().Run(ctx, CancellationToken.None);
        Assert.Equal(AvDetector.Kind, output.Kind);
        return output.Items.Cast<AvProduct>().ToList();
    }

    static FakeWmiClient NotJoined() => new FakeWmiClient().Add(@"root\cimv2", "Win32_ComputerSystem", Row(("PartOfDomain", false)));

    [Fact]
    public void Defender_via_windowsdefender_uri_is_confirmed()
    {
        var wmi = NotJoined()
            .Add(Sc, "AntiVirusProduct", Row(("displayName", "Windows Defender"), ("pathToSignedProductExe", "windowsdefender://"),
                ("productState", 397568u), ("timestamp", "Thu, 26 Nov 2026 10:00:00 GMT")))
            .Add(Def, "MSFT_MpComputerStatus", Row(("AMRunningMode", "Normal"), ("RealTimeProtectionEnabled", true)))
            .Add(Def, "MSFT_MpPreference", Row(("ExclusionPath", new[] { @"C:\Games" }), ("ExclusionExtension", Array.Empty<string>()), ("ExclusionProcess", null)));
        var src = new FakeSystemSource(_root, RegSpec.Root(), SystemWith("WinDefend"), live: true);

        var d = Run(For(src, wmi), out _).Single();
        Assert.Equal("defender", d.ItemKey);
        Assert.True(d.Confirmed);
        Assert.Equal(WscState.On, d.State);
        Assert.True(d.IsMicrosoft);
        Assert.True(d.UpToDate);
        Assert.Equal("Normal", d.DefenderMode);
        Assert.Equal("active", d.Status);
        Assert.True(d.RealTimeProtection);
        Assert.Equal("Thu, 26 Nov 2026 10:00:00 GMT", d.WscTimestamp);
        Assert.Equal([@"C:\Games"], d.Exclusions!.Paths);
        Assert.Contains("antivirus", d.Roles);
    }

    [Fact]
    public void Defender_uri_without_WinDefend_service_is_not_confirmed()
    {
        var wmi = NotJoined().Add(Sc, "AntiVirusProduct", Row(("displayName", "Windows Defender"), ("pathToSignedProductExe", "windowsdefender://"), ("productState", 397568u)));
        var d = Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith(), live: true), wmi), out _).Single();
        Assert.False(d.Confirmed);
    }

    [Fact]
    public void Stale_wsc_exe_is_unconfirmed_and_existing_exe_is_confirmed()
    {
        Directory.CreateDirectory(Path.Combine(_root, "Program Files", "Bitdefender"));
        File.WriteAllText(Path.Combine(_root, "Program Files", "Bitdefender", "wsccommunicator.exe"), "x");
        var wmi = NotJoined().Add(Sc, "AntiVirusProduct",
            Row(("displayName", "Norton 360"), ("pathToSignedProductExe", @"%ProgramFiles%\Norton\wsc_proxy.exe"), ("productState", 266240u)),
            Row(("displayName", "Bitdefender Antivirus"), ("pathToSignedProductExe", @"C:\Program Files\Bitdefender\wsccommunicator.exe"), ("productState", 266240u)));
        var items = Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith(), live: true), wmi), out _);
        Assert.False(items.Single(i => i.ItemKey == "norton").Confirmed);
        Assert.True(items.Single(i => i.ItemKey == "bitdefender").Confirmed);
        Assert.Equal("https://my.norton.com", items.Single(i => i.ItemKey == "norton").AccountUrl);
    }

    [Fact]
    public void Kaspersky_found_by_versioned_AVP_service_offline()
    {
        var items = Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("AVP21.3", "WinDefend"))), out _);
        var k = Assert.Single(items);
        Assert.Equal("kaspersky", k.ItemKey);
        Assert.False(k.Confirmed);
        Assert.Contains("Service: AVP21.3", k.Evidence);
        Assert.NotNull(k.VendorNote);
    }

    [Fact]
    public void ESET_found_by_ekrn_only()
    {
        var e = Assert.Single(Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("ekrn"))), out _));
        Assert.Equal("eset", e.ItemKey);
        Assert.Equal(["Service: ekrn"], e.Evidence);
    }

    [Fact]
    public void Malwarebytes_found_by_service_only()
    {
        var m = Assert.Single(Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("MBAMService"))), out _));
        Assert.Equal("malwarebytes", m.ItemKey);
        Assert.Null(m.State);
    }

    [Fact]
    public void WinDefend_service_alone_is_never_evidence()
    {
        Assert.Empty(Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("WinDefend", "Spooler"))), out _));
    }

    [Fact]
    public void Expired_third_party_is_reported_as_license_expired()
    {
        var wmi = NotJoined().Add(Sc, "AntiVirusProduct", Row(("displayName", "McAfee LiveSafe"), ("pathToSignedProductExe", @"C:\nope.exe"), ("productState", 0x53000u)));
        var m = Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith(), live: true), wmi), out _).Single(i => i.ItemKey == "mcafee");
        Assert.Equal(WscState.Expired, m.State);
        Assert.Equal("license expired", m.Status);
    }

    [Fact]
    public void Installed_app_names_match_including_WOW6432Node()
    {
        var sw = RegSpec.Root()
            .Key(@"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{BD}", k => k.Str("DisplayName", "Bitdefender Total Security"))
            .Key(@"Microsoft\Windows\CurrentVersion\Uninstall\Notepad++", k => k.Str("DisplayName", "Notepad++"))
            .Key(@"Microsoft\Windows\CurrentVersion\Uninstall\Reset", k => k.Str("DisplayName", "Reset Tool"));   // "ESET" must not match inside a word
        var b = Assert.Single(Run(For(new FakeSystemSource(_root, sw, SystemWith())), out _));
        Assert.Equal("bitdefender", b.ItemKey);
        Assert.Equal(["Installed app: Bitdefender Total Security"], b.Evidence);
    }

    [Fact]
    public void Evidence_from_wsc_app_and_service_merges_into_one_item()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\Uninstall\ESET", k => k.Str("DisplayName", "ESET Security"));
        var wmi = NotJoined()
            .Add(Sc, "AntiVirusProduct", Row(("displayName", "ESET Security"), ("pathToSignedProductExe", @"C:\x.exe"), ("productState", 266240u)))
            .Add(Sc, "FirewallProduct", Row(("displayName", "ESET Security"), ("pathToSignedProductExe", @"C:\x.exe"), ("productState", 266240u)));
        var e = Assert.Single(Run(For(new FakeSystemSource(_root, sw, SystemWith("ekrn"), live: true), wmi), out _), i => i.ItemKey == "eset");
        Assert.Equal(3, e.Evidence.Count);
        Assert.Equal(["antivirus", "firewall"], e.Roles);
    }

    [Fact]
    public void Unknown_wsc_product_gets_other_key()
    {
        var wmi = NotJoined().Add(Sc, "AntiVirusProduct", Row(("displayName", "Contoso Shield"), ("productState", 266240u)));
        var o = Assert.Single(Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith(), live: true), wmi), out _));
        Assert.Equal("other:contoso shield", o.ItemKey);
        Assert.Equal("Contoso Shield", o.Vendor);
    }

    [Fact]
    public void Exclusions_skipped_on_domain_joined_pc()
    {
        var wmi = new RecordingWmiClient(new FakeWmiClient()
            .Add(@"root\cimv2", "Win32_ComputerSystem", Row(("PartOfDomain", true)))
            .Add(Def, "MSFT_MpComputerStatus", Row(("AMRunningMode", "Normal"), ("RealTimeProtectionEnabled", true)))
            .Add(Def, "MSFT_MpPreference", Row(("ExclusionPath", new[] { @"C:\Secret" }))));
        var d = Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("WinDefend"), live: true), wmi), out var output).Single();
        Assert.Null(d.Exclusions);
        Assert.DoesNotContain(wmi.Calls, c => c.Wql.Contains("MSFT_MpPreference"));
        Assert.Contains(output.Notes, n => n.Contains("not read", StringComparison.Ordinal));
    }

    [Fact]
    public void Exclusions_skipped_on_entra_joined_offline_pc_unless_requested()
    {
        var sw = RegSpec.Root()
            .Key(@"Microsoft\Enrollments\{1234}", k => k.Str("UPN", "someone@example.com"))
            .Key(@"Microsoft\Windows Defender\Exclusions\Paths", k => k.Num(@"C:\Tools", 0))
            .Key(@"Microsoft\Windows Defender\Exclusions\Extensions", k => k.Num(".iso", 0))
            .Key(@"Microsoft\Windows Defender\Exclusions\Processes");
        var src = new FakeSystemSource(_root, sw, SystemWith());
        Assert.Empty(Run(For(src), out _));

        var d = Assert.Single(Run(For(src, includeDefenderPrefs: true), out _));
        Assert.Equal("defender", d.ItemKey);
        Assert.Equal([@"C:\Tools"], d.Exclusions!.Paths);
        Assert.Equal([".iso"], d.Exclusions.Extensions);
        Assert.Empty(d.Exclusions.Processes);
        Assert.Equal("offline registry", d.Exclusions.Source);
    }

    [Fact]
    public void Live_exclusions_hidden_from_standard_users_are_unknown()
    {
        var wmi = NotJoined()
            .Add(Def, "MSFT_MpComputerStatus", Row(("AMRunningMode", "Passive"), ("RealTimeProtectionEnabled", false)))
            .Add(Def, "MSFT_MpPreference", Row(("ExclusionPath", new[] { "N/A: Must be an administrator to view exclusions" })));
        var d = Assert.Single(Run(For(new FakeSystemSource(_root, RegSpec.Root(), SystemWith("WinDefend"), live: true), wmi), out _));
        Assert.Empty(d.Exclusions!.Paths);
        Assert.Equal("unknown (not elevated)", d.Exclusions.Unknown);
        Assert.StartsWith("passive", d.Status);
        Assert.False(d.Confirmed);
    }

    [Fact]
    public void Bad_data_and_failing_wmi_never_throw()
    {
        var wmi = new FakeWmiClient().Fail(Sc, "AntiVirusProduct", WmiOutcome.TimedOut).Fail(Def, "MSFT_MpComputerStatus", WmiOutcome.AccessDenied);
        var sw = RegSpec.Root().Key(@"Microsoft\Windows\CurrentVersion\Uninstall\X", k => k.Bin("DisplayName", 1, 2, 3));
        var output = new AvDetector().Run(For(new FakeSystemSource(_root, sw, null, live: true), wmi), CancellationToken.None);
        Assert.Empty(output.Items);
        Assert.NotEqual(CollectorStatus.Failed, output.Status);
        Assert.Contains(output.Notes, n => n.Contains("not elevated", StringComparison.Ordinal));
    }
}

public class AvDetectorLiveTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Category", "Live")]
    public void Live_pc_reports_defender_confirmed()
    {
        using var src = new LiveSource();
        var ctx = For(src, new WmiClient());
        var result = new AvDetector().Run(ctx, CancellationToken.None);
        var items = result.Items.Cast<AvProduct>().ToList();
        output.WriteLine($"products={items.Count} confirmed={items.Count(i => i.Confirmed)} warnings={ctx.Warnings.Count} notes={result.Notes.Count}");
        var d = Assert.Single(items, i => i.ItemKey == AvVendors.DefenderId);
        output.WriteLine($"defender: confirmed={d.Confirmed} state={d.State} mode={d.DefenderMode}");
        Assert.True(d.Confirmed);
    }
}
