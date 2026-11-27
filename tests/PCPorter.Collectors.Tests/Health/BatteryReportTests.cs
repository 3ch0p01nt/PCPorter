using PCPorter.Collectors.Health;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Health;

/// <summary>Fixtures follow the powercfg /batteryreport /xml layout; serials and names are made up.</summary>
public class BatteryReportTests : IDisposable
{
    readonly string _work = Directory.CreateTempSubdirectory("pcporter-battery").FullName;
    public void Dispose() => Directory.Delete(_work, true);

    static string Report(params string[] batteries) => $"""
        <?xml version="1.0" encoding="utf-8"?>
        <BatteryReport xmlns="http://schemas.microsoft.com/battery/2012">
          <ReportInformation><ReportVersion>1</ReportVersion></ReportInformation>
          <Batteries>{string.Concat(batteries)}</Batteries>
        </BatteryReport>
        """;

    static string Battery(string id, string design, string full, string? cycles) => $"""
        <Battery><Id>{id}</Id><Manufacturer>ACME</Manufacturer><SerialNumber>SCRUBBED</SerialNumber><Chemistry>LION</Chemistry>
        <DesignCapacity>{design}</DesignCapacity><FullChargeCapacity>{full}</FullChargeCapacity>{(cycles is null ? "" : $"<CycleCount>{cycles}</CycleCount>")}</Battery>
        """;

    [Fact]
    public void One_battery()
    {
        var b = Assert.Single(BatteryReport.Parse(Report(Battery("Main", "50000", "45000", "120")))!);
        Assert.Equal(new BatteryInfo("Main", "ACME", "LION", 50000, 45000, 120, 90), b);
    }

    [Fact]
    public void Two_batteries()
    {
        var list = BatteryReport.Parse(Report(Battery("A", "30000", "15000", "500"), Battery("B", "20000", "19000", "10")))!;
        Assert.Equal([50, 95], list.Select(b => b.HealthPercent!.Value));
    }

    [Fact]
    public void No_battery_is_null() => Assert.Null(BatteryReport.Parse(Report()));

    [Fact]
    public void Missing_or_zero_cycles_are_null()
    {
        var list = BatteryReport.Parse(Report(Battery("A", "50000", "40000", null), Battery("B", "50000", "40000", "0")))!;
        Assert.All(list, b => Assert.Null(b.CycleCount));
    }

    [Fact]
    public void Over_capacity_is_clamped_to_100()
    {
        var b = Assert.Single(BatteryReport.Parse(Report(Battery("New", "50000", "52500", "3")))!);
        Assert.Equal(100, b.HealthPercent);
    }

    [Fact]
    public void Runs_powercfg_into_the_work_folder_and_removes_the_report()
    {
        var expected = Path.Combine(_work, "battery.xml");
        var runner = new FakeProcessRunner((exe, args) =>
        {
            File.WriteAllText(args[3], Report(Battery("Main", "50000", "45000", "120")));
            return new ProcessResult(0, "", false);
        });
        var list = BatteryReport.Read(runner, new FakeWmiClient(), _work, new List<string>(), new Dictionary<string, string>());
        Assert.Single(list!);
        Assert.Equal($"powercfg.exe /batteryreport /xml /output {expected}", Assert.Single(runner.Started));
        Assert.False(File.Exists(expected));
    }

    [Fact]
    public void Failed_powercfg_falls_back_to_wmi_and_never_throws()
    {
        var runner = new FakeProcessRunner((_, _) => new ProcessResult(1, "", false));
        var wmi = new FakeWmiClient()
            .Add(WmiProfile.WmiNs, "BatteryStaticData", TestContexts.Row(("DesignedCapacity", 50000u), ("DeviceName", "B1")))
            .Add(WmiProfile.WmiNs, "BatteryFullChargedCapacity", TestContexts.Row(("FullChargedCapacity", 40000u)));
        var warnings = new List<string>();
        var b = Assert.Single(BatteryReport.Read(runner, wmi, _work, warnings, new Dictionary<string, string>())!);
        Assert.Equal(80, b.HealthPercent);
        Assert.NotEmpty(warnings);
    }

    [Fact]
    public void Garbage_report_is_a_warning()
    {
        var runner = new FakeProcessRunner((_, args) => { File.WriteAllText(args[3], "<not xml"); return new ProcessResult(0, "", false); });
        var warnings = new List<string>();
        Assert.Null(BatteryReport.Read(runner, new FakeWmiClient(), _work, warnings, new Dictionary<string, string>()));
        Assert.Single(warnings);
    }
}
