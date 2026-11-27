using PCPorter.Collectors;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Health;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Security;
using PCPorter.Collectors.Signing;
using PCPorter.Collectors.Sources;

namespace PCPorter.Reports;

/// <summary>Wires the concrete collectors, the signature checker and the report for a health &amp; security scan.</summary>
public static class ScanSetup
{
    /// <param name="now">Fixed "now" for date-based checks (crash history, Windows support, backups); null = the real clock.</param>
    public static IReadOnlyList<ICollector> Collectors(ISystemSource source, DateTimeOffset? now = null) =>
    [
        new ProfileCollector(clock: now is { } n ? () => n : null),
        new AvDetector(),
        new SecurityPostureCollector(new PostureOptions(Now: now)),
        new PersistenceCollector(),
        new AppInventoryCollector(),
    ];

    /// <summary>Live: this PC's catalog database. Offline: catalogs read from the scanned drive's CatRoot.</summary>
    public static ISignatureChecker Signatures(ISystemSource source) =>
        source.IsLive ? new AuthenticodeChecker() : new AuthenticodeChecker(new OfflineCatalogIndex(source.ReadRoot));

    public static ScanJobResult Run(string outRoot, ScanJobOptions options, IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
        ScanJob.Run(outRoot, options, s => Collectors(s, options.Now), Signatures, progress, ct, HealthReport.Write);

    /// <summary>The same counts the report's banner shows (one decision: <see cref="Assessment"/>).</summary>
    public static FindingCounts CountFindings(ScanJobResult r) => Assessment.Of(r).Counts();
}
