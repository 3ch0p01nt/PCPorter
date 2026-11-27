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
            Assert.Throws<InvalidDataException>(() => ScanJob.Run(_out, new ScanJobOptions(OfflineRoot: empty), _ => []));
            Assert.False(Directory.Exists(Path.Combine(_out, "PCPorter")));
        }
        finally { Directory.Delete(empty, true); }
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
