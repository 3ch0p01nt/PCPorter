using System.Security.Principal;
using PCPorter.Reports;
using Xunit.Abstractions;

namespace PCPorter.Reports.Tests;

/// <summary>Developer harness: runs the real gallery job on this PC only when PCPORTER_LOCAL_OUT is set.</summary>
public sealed class LocalRunFactAttribute : FactAttribute
{
    public LocalRunFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PCPORTER_LOCAL_OUT")))
            Skip = "Set PCPORTER_LOCAL_OUT to a local (non-synced) folder to run against this PC.";
    }
}

public class LocalRunHarness(ITestOutputHelper output)
{
    sealed class Sink : IProgress<string> { public void Report(string v) { } }   // progress names may include paths: not printed

    [LocalRunFact]
    [Trait("Category", "Manual")]
    public void Run_gallery_job_on_this_pc()
    {
        var outDir = Environment.GetEnvironmentVariable("PCPORTER_LOCAL_OUT")!;
        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        var web = Environment.GetEnvironmentVariable("PCPORTER_LOCAL_NOWEB") is null;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = ThumbnailJob.Run(outDir, progress: new Sink(),
            options: GalleryJobFactory.Options(new GalleryJobFactory.Settings(Web: web), elevated));
        var items = r.Scan.Items;
        output.WriteLine($"REPORT {r.ReportPath}");
        output.WriteLine($"ELAPSED {sw.Elapsed.TotalSeconds:F0}s elevated={elevated}");
        output.WriteLine($"KINDS {string.Join(", ", items.GroupBy(i => i.Kind).Select(g => $"{g.Key}={g.Count()}"))}");
        output.WriteLine($"STATUS {string.Join(", ", items.Where(i => i.Kind == "thumbnail").GroupBy(i => i.Status).Select(g => $"{g.Key}={g.Count()}"))}");
        output.WriteLine($"NOPICTURE {items.Count(i => !i.HasImage)} FREESPACE {items.Count(i => i.FoundInFreeSpace)} DUPGROUPED {items.Count(i => i.DupGroup != null)}");
        output.WriteLine($"WARNINGS {r.Scan.Warnings.Count} NOTES {r.Scan.Notes.Count}");
        foreach (var n in r.Scan.Notes) output.WriteLine("NOTE " + n);
        Assert.True(File.Exists(r.ReportPath));
    }
}
