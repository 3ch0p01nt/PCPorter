using PCPorter.Collectors.Health;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;
using Xunit.Abstractions;
using static PCPorter.Collectors.Tests.Health.TestContexts;

namespace PCPorter.Collectors.Tests.Health;

public class ProfileCollectorTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-profile").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    static readonly EventQuery NoEvents = (_, _, _, _) => [];

    [Fact]
    public void Offline_uses_hives_only_and_never_queries_wmi_or_starts_programs()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion", k => k
            .Str("ProductName", "Windows 10 Enterprise").Str("EditionID", "Enterprise").Str("CurrentBuildNumber", "26200"));
        var wmi = new FakeWmiClient();
        var runner = new FakeProcessRunner((_, _) => throw new InvalidOperationException("must not run"));
        var ctx = For(new FakeSystemSource(_root, sw, SystemHive()), wmi, runner);
        var output = new ProfileCollector(_ => throw new InvalidOperationException("no monitors offline"), NoEvents).Run(ctx, CancellationToken.None);

        Assert.Equal(ProfileCollector.Kind, output.Kind);
        var p = Assert.IsType<PcProfile>(Assert.Single(output.Items));
        Assert.Equal("profile", p.ItemKey);
        Assert.Equal("Windows 11 Enterprise", p.OsName);
        Assert.Empty(wmi.Queries);
        Assert.Empty(runner.Started);
        Assert.Null(p.Processor);
        Assert.Null(p.Batteries);
        Assert.NotEmpty(output.Notes);
    }

    [Fact]
    public void Live_with_everything_failing_is_partial_not_an_exception()
    {
        var wmi = new FakeWmiClient()
            .Fail(WmiProfile.TpmNs, "Win32_Tpm", WmiOutcome.AccessDenied)
            .Fail(WmiProfile.Cimv2, "SoftwareLicensingProduct", WmiOutcome.TimedOut);
        var runner = new FakeProcessRunner((_, _) => new ProcessResult(-1, "", true));
        var ctx = For(new FakeSystemSource(_root, null, null, live: true), wmi, runner, Path.Combine(_root, "work"));
        var output = new ProfileCollector(_ => throw new InvalidOperationException("display APIs broke"),
            (_, _, _, _) => throw new IOException("log broke")).Run(ctx, CancellationToken.None);

        var p = Assert.IsType<PcProfile>(Assert.Single(output.Items));
        Assert.Equal(CollectorStatus.Partial, output.Status);
        Assert.Equal(PcProfile.NotElevated, p.Unknown["tpm"]);
        Assert.Null(p.Activated);
        Assert.NotEmpty(ctx.Warnings);
        Assert.Single(runner.Started, s => s.StartsWith("powercfg.exe /batteryreport /xml /output ", StringComparison.Ordinal));
    }

    [Fact]
    public void Live_merges_monitors_and_battery()
    {
        var work = Path.Combine(_root, "work");
        var runner = new FakeProcessRunner((_, args) =>
        {
            File.WriteAllText(args[3], """
                <?xml version="1.0" encoding="utf-8"?>
                <BatteryReport xmlns="http://schemas.microsoft.com/battery/2012"><Batteries><Battery><Id>B</Id><DesignCapacity>100</DesignCapacity><FullChargeCapacity>75</FullChargeCapacity><CycleCount>9</CycleCount></Battery></Batteries></BatteryReport>
                """);
            return new ProcessResult(0, "", false);
        });
        var ctx = For(new FakeSystemSource(_root, null, null, live: true), new FakeWmiClient(), runner, work);
        var output = new ProfileCollector(_ => [new NativeMonitor("Panel", 2560, 1600, 150, null)], NoEvents).Run(ctx, CancellationToken.None);
        var p = (PcProfile)output.Items.Single();
        Assert.Equal(75, p.Batteries!.Single().HealthPercent);
        Assert.Equal(new MonitorInfo("Panel", 2560, 1600, 150, null, null), p.Monitors!.Single());
        Assert.Equal(0, p.Crashes!.BugChecks90Days);
    }

    [Fact]
    public void Cancelled_before_wmi()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var output = new ProfileCollector(_ => [], NoEvents).Run(For(new FakeSystemSource(_root, live: true)), cts.Token);
        Assert.Equal(CollectorStatus.Cancelled, output.Status);
    }
}

public class ProfileCollectorLiveTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Category", "Live")]
    public void Live_pc_is_windows_11()
    {
        using var src = new LiveSource();
        var work = Directory.CreateTempSubdirectory("pcporter-live-profile").FullName;
        try
        {
            var ctx = For(src, new WmiClient(), new ProcessRunner(), work);
            var result = new ProfileCollector().Run(ctx, CancellationToken.None);
            var p = (PcProfile)result.Items.Single();
            output.WriteLine($"os={p.OsName} build={p.Build} arch={p.Architecture} status={result.Status} warnings={ctx.Warnings.Count} unknown={p.Unknown.Count}");
            output.WriteLine($"gpus={p.Gpus?.Count} physicalDisks={p.PhysicalDisks?.Count} logicalDisks={p.LogicalDisks?.Count} monitors={p.Monitors?.Count} " +
                $"batteries={p.Batteries?.Count} problemDevices={p.ProblemDevices?.Count} bugchecks90d={p.Crashes?.BugChecks90Days} kp41={p.Crashes?.UnexpectedShutdowns} " +
                $"tpm={p.TpmVersion ?? (p.Unknown.TryGetValue("tpm", out var t) ? t : "null")} activated={p.Activated} secureBoot={p.SecureBoot}");
            foreach (var w in ctx.Warnings) output.WriteLine("warning: " + w.Split(':')[0] + ":" + (w.Split(':').ElementAtOrDefault(1) ?? ""));
            Assert.StartsWith("Windows 11", p.OsName);
            Assert.InRange(p.Build!.Value, 26000, 26999);
            Assert.Empty(Directory.EnumerateFiles(work));   // battery report removed
        }
        finally { Directory.Delete(work, true); }
    }
}
