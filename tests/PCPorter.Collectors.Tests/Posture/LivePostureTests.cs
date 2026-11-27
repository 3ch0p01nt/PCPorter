using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Sources;
using Xunit.Abstractions;

namespace PCPorter.Collectors.Tests.Posture;

/// <summary>Runs the real collector over this PC (no admin needed). Prints check ids and statuses only - never paths or names.</summary>
[Trait("Category", "Live")]
public class LivePostureTests(ITestOutputHelper output)
{
    [Fact]
    public void Reviews_this_pcs_security_settings()
    {
        using var src = new LiveSource();
        var warnings = new List<string>();
        var ctx = new CollectorContext(src, new WmiClient(), new ProcessRunner(), new NoSignatureChecker(), Path.GetTempPath(), warnings);
        var result = new SecurityPostureCollector().Run(ctx, CancellationToken.None);
        var checks = result.Items.Cast<PostureCheck>().ToList();

        Assert.NotEqual(CollectorStatus.Failed, result.Status);
        Assert.True(checks.Count >= 21, $"only {checks.Count} checks");
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Finding)));
        output.WriteLine($"status={result.Status} checks={checks.Count} warnings={warnings.Count}");
        foreach (var c in checks.Where(c => !c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal)))
            output.WriteLine($"{c.Id}={c.Status}");
        output.WriteLine($"forced-extension-items={checks.Count(c => c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal))}");
    }
}
