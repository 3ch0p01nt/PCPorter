using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using PCPorter.Collectors;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Core.Security;

namespace PCPorter.Reports;

public sealed record ScanJobOptions(
    string? OfflineRoot = null,                 // null = this running PC
    bool IncludeDefenderPreferences = false,
    bool Elevated = false,
    TimeSpan? PerCollectorLimit = null,
    DateTimeOffset? Now = null);                // fixed "now" for date-based checks (tests); null = the real clock

public sealed record ScanJobResult(string CaseFolder, string ScanId, ScanRunResult Run, IReadOnlyList<string> Warnings,
    IReadOnlyList<string> SourceNotes, string? ReportPath, string ActivityPath, string? ScannedComputer, bool Offline);

/// <summary>
/// Health &amp; security scan: opens the source first (a bad drive never leaves an empty case), then a private case
/// folder named after the SCANNED PC, case.db (scan row written before collectors run), redacted items, JSON exports,
/// an activity log for IT and HealthReport.html. All file access is confined to the scanned drive.
/// </summary>
public static partial class ScanJob
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    [GeneratedRegex("[^a-z0-9_-]")]
    private static partial Regex UnsafeFileChars();

    public static ScanJobResult Run(string outRoot, ScanJobOptions options,
        Func<ISystemSource, IReadOnlyList<ICollector>> collectorsFor,
        Func<ISystemSource, ISignatureChecker>? signaturesFor = null,
        IProgress<ScanProgress>? progress = null, CancellationToken ct = default,
        Action<ScanJobResult, CollectorContext>? writeReport = null)
    {
        var started = DateTimeOffset.UtcNow;
        using ISystemSource source = options.OfflineRoot is null ? new LiveSource() : new OfflineSource(options.OfflineRoot);
        using var confine = SourceFiles.Confine(source.ReadRoot);

        var software = source.OpenHive(Hive.Software);
        var computer = source.OpenHive(Hive.System)?.Open($@"{source.CurrentControlSet()}\Control\ComputerName\ComputerName")?.GetString("ComputerName");
        var version = typeof(ScanJob).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev";
        var scanId = Guid.NewGuid().ToString("N")[..12];
        var info = new ScanInfo(scanId, started, version, source.IsLive ? "live" : "offline",
            software?.Open(@"Microsoft\Cryptography")?.GetString("MachineGuid"), computer,
            software?.Open(@"Microsoft\Windows NT\CurrentVersion")?.GetString("CurrentBuild"), source.ReadRoot);

        var folder = CaseFolder.Create(outRoot, started, computer ?? (source.IsLive ? Environment.MachineName : "OldPC"));
        var work = Path.Combine(folder.Path, "work");
        var scanDir = Path.Combine(folder.Path, "scan");
        try
        {
            CaseFolder.CreatePrivate(work);
            CaseFolder.CreatePrivate(scanDir);
            var warnings = new List<string>(folder.Warnings);
            var activity = new List<object>();
            IWmiClient wmi = source.IsLive ? new LoggingWmiClient(new WmiClient(), activity) : new OfflineWmiClient();
            var ctx = new CollectorContext(source, wmi, new LoggingProcessRunner(new ProcessRunner(), activity),
                signaturesFor?.Invoke(source) ?? new NoSignatureChecker(), work, warnings, null, options.IncludeDefenderPreferences);
            using var signatures = ctx.Signatures as IDisposable;

            ScanRunResult run;
            using (var db = CaseDb.Open(Path.Combine(folder.Path, "case.db")))
            {
                db.BeginScan(info);                                   // a crash mid-scan still leaves a 'running' row
                run = new ScanRunner(collectorsFor(source), options.PerCollectorLimit).Run(ctx, progress, ct);
                var kindsUsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                db.RunInTransaction(() =>
                {
                    foreach (var r in run.Runs)
                    {
                        db.RecordCollector(scanId, r.Collector, r.Status.ToString(), r.Items, r.Ms, r.Message);
                        if (r.Output is not { } o) continue;
                        var kind = UniqueKind(o.Kind, kindsUsed);
                        var nodes = o.Items.Select(i => (i.ItemKey, Node: RedactStrings(JsonSerializer.SerializeToNode(i, i.GetType(), Json)))).ToList();
                        db.SaveItems(scanId, nodes.Select(n => new ScanItemRow(kind, n.ItemKey, n.Node?.ToJsonString() ?? "null")));
                        var export = new JsonObject
                        {
                            ["schemaVersion"] = 1, ["kind"] = kind, ["scanId"] = scanId, ["toolVersion"] = version,
                            ["generatedUtc"] = DateTimeOffset.UtcNow,
                            ["source"] = new JsonObject { ["mode"] = info.SourceMode, ["computerName"] = info.ComputerName, ["osBuild"] = info.OsBuild },
                            ["items"] = new JsonArray(nodes.Select(n => n.Node).ToArray()),
                        };
                        File.WriteAllText(Path.Combine(scanDir, kind + ".json"), export.ToJsonString());
                    }
                    db.FinishScan(scanId, DateTimeOffset.UtcNow, run.Overall);
                });
            }

            var activityPath = Path.Combine(scanDir, "activity.json");
            File.WriteAllText(activityPath, JsonSerializer.Serialize(new
            {
                explanation = "Everything PCPorter asked Windows during this scan. All read-only: WMI queries and helper programs listed here; registry and files were only read.",
                sourceMode = info.SourceMode, actions = activity,
            }, new JsonSerializerOptions(Json) { WriteIndented = true }));

            var result = new ScanJobResult(folder.Path, scanId, run, warnings, source.Notes, null, activityPath, computer, !source.IsLive);
            if (writeReport is not null)
            {
                writeReport(result, ctx);
                var report = Path.Combine(folder.Path, "HealthReport.html");
                if (File.Exists(report)) result = result with { ReportPath = report };
            }
            return result;
        }
        finally
        {
            try { if (Directory.Exists(work)) Directory.Delete(work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    static string UniqueKind(string kind, HashSet<string> used)
    {
        var safe = UnsafeFileChars().Replace(kind.ToLowerInvariant(), "_");
        if (safe is "" or "activity") safe = "items";
        var name = safe;
        for (int n = 2; !used.Add(name); n++) name = $"{safe}_{n}";
        return name;
    }

    /// <summary>Masks secrets in every string value (command lines, task arguments...) without breaking the JSON.</summary>
    public static JsonNode? RedactStrings(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var key in o.Select(p => p.Key).ToList()) o[key] = RedactStrings(o[key]?.DeepClone());
                return o;
            case JsonArray a:
                for (int i = 0; i < a.Count; i++) a[i] = RedactStrings(a[i]?.DeepClone());
                return a;
            case JsonValue v when v.TryGetValue<string>(out var s):
                var r = Redactor.Redact(s);
                return ReferenceEquals(r, s) || r == s ? v : JsonValue.Create(r);
            default:
                return node;
        }
    }

    /// <summary>Records every WMI query (namespace + query text) for the activity log.</summary>
    sealed class LoggingWmiClient(IWmiClient inner, List<object> log) : IWmiClient
    {
        public WmiResult Query(string ns, string wql, TimeSpan? timeout = null)
        {
            var r = inner.Query(ns, wql, timeout);
            lock (log) log.Add(new { type = "wmi", ns, query = Redactor.Redact(wql), outcome = r.Outcome.ToString(), rows = r.Rows.Count });
            return r;
        }
    }

    sealed class LoggingProcessRunner(IProcessRunner inner, List<object> log) : IProcessRunner
    {
        public ProcessResult Run(string system32Exe, IReadOnlyList<string> args, TimeSpan timeout)
        {
            var r = inner.Run(system32Exe, args, timeout);
            lock (log) log.Add(new { type = "process", program = Path.GetFileName(system32Exe), args = args.Select(Redactor.Redact), exitCode = r.ExitCode, r.TimedOut });
            return r;
        }
    }
}
