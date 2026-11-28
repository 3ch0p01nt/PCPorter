using System.Text.Json;
using PCPorter.Collectors;
using PCPorter.Core.Case;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class ScanJobTests : IDisposable
{
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-scanjob").FullName;
    public void Dispose() { try { Directory.Delete(_out, true); } catch (IOException) { } }

    sealed record Thing(string ItemKey, string Command) : IScanItem;

    sealed class Fake(string name, Func<CollectorOutput> run) : ICollector
    {
        public string Name => name;
        public CollectorOutput Run(CollectorContext context, CancellationToken ct) => run();
    }

    [Fact]
    public void End_to_end_with_a_failing_collector_and_a_secret()
    {
        IReadOnlyList<ICollector> Collectors(PCPorter.Collectors.Sources.ISystemSource _) =>
        [
            new Fake("Things", () => new CollectorOutput("things", [new Thing("t1", "sync.exe --password=Hunter2")], [])),
            new Fake("Broken", () => throw new IOException("disk said token=abc")),
        ];

        var r = ScanJob.Run(_out, new ScanJobOptions(), Collectors);

        Assert.Equal("partial", r.Run.Overall);
        Assert.False(Directory.Exists(Path.Combine(r.CaseFolder, "work")));                 // cleaned up
        var export = File.ReadAllText(Path.Combine(r.CaseFolder, "scan", "things.json"));
        Assert.DoesNotContain("Hunter2", export);                                             // redacted, still valid JSON
        using var doc = JsonDocument.Parse(export);
        Assert.Equal("t1", doc.RootElement.GetProperty("items")[0].GetProperty("itemKey").GetString());
        Assert.True(File.Exists(r.ActivityPath));
        JsonDocument.Parse(File.ReadAllText(r.ActivityPath)).Dispose();

        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var scan = Assert.Single(db.Scans());
        Assert.Equal("partial", scan.Status);
        Assert.Equal("live", scan.Mode);
        var item = Assert.Single(db.Items(r.ScanId, "things"));
        Assert.DoesNotContain("Hunter2", item.Json);
        Assert.Contains(r.Warnings, w => w.Contains("Broken") && !w.Contains("abc"));
    }

    [Fact]
    public void A_bad_offline_drive_creates_no_case_folder()
    {
        var empty = Directory.CreateTempSubdirectory("pcporter-notwindows").FullName;
        try
        {
            Assert.Throws<PCPorter.Core.SourceRejectedException>(() => ScanJob.Run(_out, new ScanJobOptions(OfflineRoot: empty), _ => []));
            Assert.False(Directory.Exists(Path.Combine(_out, "PCPorter")));
        }
        finally { Directory.Delete(empty, true); }
    }

    [Fact]
    public void Saving_inside_the_scanned_drive_is_refused_before_anything_is_written()
    {
        using var drive = PCPorter.TestKit.OldPcDrive.Create();
        var inside = Path.Combine(drive.Root, "Cases");
        var ex = Assert.Throws<CaseLocationRejectedException>(() => ScanJob.Run(inside, new ScanJobOptions(OfflineRoot: drive.Root), _ => []));
        Assert.Contains("drive being checked", ex.Message);
        Assert.False(Directory.Exists(inside));
    }

    static ScanJobResult Result(bool offline, params CollectorStatus[] statuses) =>
        new("case", "id", new ScanRunResult(statuses.Select((s, i) => new CollectorRun($"c{i}", s, 0, 0, null, null)).ToList()), [], [], null, "", null, offline);

    static ScanJobResult WithFinding(ScanJobResult r) => r with
    {
        Run = new ScanRunResult([.. r.Run.Runs, new CollectorRun("Settings", CollectorStatus.Ok, 1, 0, null, new CollectorOutput("posture",
            [new PCPorter.Collectors.Posture.PostureCheck("fw", "Firewall", PCPorter.Collectors.Posture.PostureStatus.Risk, PCPorter.Collectors.Posture.PostureSeverity.High, "Off.", "On.", "")], []))]),
    };

    [Theory]
    [InlineData(false, new[] { CollectorStatus.Ok, CollectorStatus.SkippedOffline }, ScanOutcome.Ok, "ok", 0)]
    [InlineData(true, new[] { CollectorStatus.Ok, CollectorStatus.Ok }, ScanOutcome.OkWithLimits, "partial", 1)]     // offline: always "with limits", exit 1
    [InlineData(true, new[] { CollectorStatus.Partial, CollectorStatus.Ok }, ScanOutcome.Partial, "partial", 1)]
    [InlineData(false, new[] { CollectorStatus.Ok, CollectorStatus.TimedOut }, ScanOutcome.Partial, "partial", 1)]
    [InlineData(true, new[] { CollectorStatus.Ok, CollectorStatus.Cancelled }, ScanOutcome.Cancelled, "cancelled", 6)]
    public void One_outcome_status_and_exit_code_per_scan(bool offline, CollectorStatus[] statuses, ScanOutcome outcome, string status, int exit)
    {
        var r = Result(offline, statuses);
        Assert.Equal(outcome, r.Outcome);
        Assert.Equal(status, r.Status);
        Assert.Equal(exit, ScanJob.ExitCode(r, failOn: null));
        Assert.Equal(offline && outcome == ScanOutcome.OkWithLimits, r.CheckedWithLimits);
    }

    [Fact]
    public void Fail_on_findings_beats_partial_and_offline_but_not_cancel()
    {
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.FindingsFound, ScanJob.ExitCode(WithFinding(Result(true, CollectorStatus.Ok)), "high"));
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.FindingsFound, ScanJob.ExitCode(WithFinding(Result(false, CollectorStatus.Failed)), "unusual"));
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Partial, ScanJob.ExitCode(WithFinding(Result(true, CollectorStatus.Ok)), null));
        Assert.Equal(PCPorter.Core.Cli.ExitCodes.Cancelled, ScanJob.ExitCode(WithFinding(Result(false, CollectorStatus.Cancelled)), "high"));
    }

    [Fact]
    public void Redaction_keeps_json_valid_with_escaped_quotes()
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse("""{"cmd":"x --password=\"abc def\" --token=zzz","n":1,"list":["pwd=1"]}""");
        var red = ScanJob.RedactStrings(node)!.ToJsonString();
        using var doc = JsonDocument.Parse(red);
        Assert.DoesNotContain("zzz", red);
        Assert.Equal(1, doc.RootElement.GetProperty("n").GetInt32());
    }
}
