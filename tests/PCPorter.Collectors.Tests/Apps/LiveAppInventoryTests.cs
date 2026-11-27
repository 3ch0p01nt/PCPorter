using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Sources;
using Xunit.Abstractions;

namespace PCPorter.Collectors.Tests.Apps;

/// <summary>Runs the real collector over this PC (no admin needed). Prints counts only - never names or paths.</summary>
[Trait("Category", "Live")]
public class LiveAppInventoryTests(ITestOutputHelper output)
{
    [Fact]
    public void Lists_this_pcs_apps()
    {
        using var src = new LiveSource();
        var work = Directory.CreateTempSubdirectory("pcporter-apps-live").FullName;
        try
        {
            var winget = Environment.GetEnvironmentVariable("PCPORTER_TEST_WINGET") == "1";
            var (apps, result, warnings) = AppTest.Run(src, work, new AppInventoryOptions(Winget: winget));

            Assert.True(apps.Count > 10, $"only {apps.Count} apps");
            Assert.All(apps, a => Assert.False(string.IsNullOrWhiteSpace(a.ItemKey)));
            Assert.NotEqual(CollectorStatus.Failed, result.Status);
            output.WriteLine($"status={result.Status} total={apps.Count} warnings={warnings.Count} notes={result.Notes.Count}");
            foreach (var g in apps.GroupBy(a => a.Kind).OrderBy(g => g.Key))
                output.WriteLine($"{g.Key}={g.Count()}");
            output.WriteLine($"hidden={apps.Count(a => a.Hidden)} reinstall={apps.Count(a => a.ReinstallCandidate)} " +
                             $"user-scope={apps.Count(a => a.Scope.StartsWith("User:"))} x86={apps.Count(a => a.Architecture == "x86")} " +
                             $"inferredDate={apps.Count(a => a.InstallDateInferred)} productCode={apps.Count(a => a.ProductCode is not null)} " +
                             $"choco={apps.Count(a => a.ChocoId is not null)} scoop={apps.Count(a => a.ScoopId is not null)} winget={apps.Count(a => a.WingetId is not null)}");
        }
        finally { Directory.Delete(work, true); }
    }
}
