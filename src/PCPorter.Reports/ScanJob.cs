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

/// <summary>How a finished scan went: one decision for the report, the app page, the CLI exit code and case.db.</summary>
public enum ScanOutcome
{
    /// <summary>Every part was checked.</summary>
    Ok,
    /// <summary>An offline scan where every part ran: all a drive can tell was read, but antivirus state and hardware
    /// health only exist on a running PC. Not a problem, and not a full check either (status "partial", exit 1).</summary>
    OkWithLimits,
    /// <summary>A part failed, ran out of time or could only read some of its data.</summary>
    Partial,
    /// <summary>The user stopped the scan.</summary>
    Cancelled,
}

public sealed record ScanJobResult(string CaseFolder, string ScanId, ScanRunResult Run, IReadOnlyList<string> Warnings,
    IReadOnlyList<string> SourceNotes, string? ReportPath, string ActivityPath, string? ScannedComputer, bool Offline)
{
    public ScanOutcome Outcome => ScanJob.OutcomeOf(Run, Offline);

    /// <summary>"ok", "partial" or "cancelled" (case.db and the CLI JSON). An offline scan is never "ok": see <see cref="ScanOutcome.OkWithLimits"/>.</summary>
    public string Status => ScanJob.StatusOf(Outcome);

    /// <summary>True for an offline scan where every part ran: the app says "checked from the drive" instead of "all parts were checked".</summary>
    public bool CheckedWithLimits => Outcome == ScanOutcome.OkWithLimits;
}

/// <summary>
/// The scan failed after its case folder was created. <see cref="Exception.InnerException"/> is the cause (its message
/// is this message; redact before showing). <see cref="CaseFolderPath"/> is the kept case folder when results were
/// already saved in it (case.db and the scan exports; the report may be missing), or null when nothing useful had been
/// written and the folder was removed.
/// </summary>
public sealed class ScanJobFailedException(string? caseFolderPath, Exception inner) : Exception(inner.Message, inner)
{
    public string? CaseFolderPath { get; } = caseFolderPath;
}

/// <summary>
/// Health &amp; security scan: opens the source first (a bad drive never leaves an empty case), then a private case
/// folder named after the SCANNED PC, case.db (scan row written before collectors run), redacted items, JSON exports,
/// an activity log for IT and HealthReport.html. All file access is confined to the scanned drive.
/// Errors: <see cref="CaseLocationRejectedException"/> (bad save folder, including one on the scanned drive) and
/// <see cref="PCPorter.Core.SourceRejectedException"/> (bad drive) before anything is written; any failure after the
/// case folder exists is a <see cref="ScanJobFailedException"/> that names the kept folder, or none if it was removed.
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
        // The same rule for the app and the CLI: never write the case onto the drive being checked (by volume
        // identity, so a subst letter or mount point of that drive is refused too). Checked before anything is opened.
        var location = CaseLocation.Check(outRoot, options.OfflineRoot);
        if (!location.IsAllowed) throw new CaseLocationRejectedException(location.Reason!);
        using ISystemSource source = options.OfflineRoot is null ? new LiveSource() : new OfflineSource(options.OfflineRoot);
        using var confine = SourceFiles.Confine(source.ReadRoot);

        var software = source.OpenHive(Hive.Software);
        var computer = source.OpenHive(Hive.System)?.Open($@"{source.CurrentControlSet()}\Control\ComputerName\ComputerName")?.GetString("ComputerName");
        // The full stamped version (0.1.0+<commit date>.<hash>), so a report says which build made it.
        var version = typeof(ScanJob).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "dev";
        var scanId = Guid.NewGuid().ToString("N")[..12];
        var info = new ScanInfo(scanId, started, version, source.IsLive ? "live" : "offline",
            software?.Open(@"Microsoft\Cryptography")?.GetString("MachineGuid"), computer,
            software?.Open(@"Microsoft\Windows NT\CurrentVersion")?.GetString("CurrentBuild"), source.ReadRoot);

        var folder = CaseFolder.Create(outRoot, started, computer ?? (source.IsLive ? Environment.MachineName : "OldPC"));
        var work = CaseFolder.WorkFolderFor(folder.Path);              // temporary copies: on the system drive, not the save drive
        var scanDir = Path.Combine(folder.Path, "scan");
        bool saved = false;                                           // case.db and the exports hold this scan's results
        try
        {
            CaseFolder.CreateWork(folder.Path);
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
                    db.FinishScan(scanId, DateTimeOffset.UtcNow, StatusOf(OutcomeOf(run, !source.IsLive)));
                });
            }
            saved = true;

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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Nothing useful yet: remove the empty case so no unnamed folder is left behind. Otherwise keep the saved
            // results and say where they are.
            if (!saved && TryDelete(folder.Path)) throw new ScanJobFailedException(null, ex);
            throw new ScanJobFailedException(folder.Path, ex);
        }
        catch (OperationCanceledException)
        {
            if (!saved) TryDelete(folder.Path);
            throw;
        }
        finally
        {
            try { if (Directory.Exists(work)) Directory.Delete(work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    public static ScanOutcome OutcomeOf(ScanRunResult run, bool offline) =>
        run.Cancelled ? ScanOutcome.Cancelled
        : run.AnyFailed || run.AnyPartial ? ScanOutcome.Partial
        : offline ? ScanOutcome.OkWithLimits
        : ScanOutcome.Ok;

    public static string StatusOf(ScanOutcome o) => o switch { ScanOutcome.Ok => "ok", ScanOutcome.Cancelled => "cancelled", _ => "partial" };

    /// <summary>
    /// The <c>scan</c> command's exit code. Order: 6 cancelled; 5 findings at the <paramref name="failOn"/> level ("high":
    /// worth a look or fix this; "unusual": also unusual), which beats partial so --fail-on still reports what an offline
    /// or partial scan found; 1 partial, including every offline scan (a drive alone cannot show antivirus state or
    /// hardware health); 0 ok.
    /// </summary>
    public static int ExitCode(ScanJobResult r, string? failOn)
    {
        var outcome = r.Outcome;
        if (outcome == ScanOutcome.Cancelled) return PCPorter.Core.Cli.ExitCodes.Cancelled;
        if (failOn is not null)
        {
            var f = Assessment.Of(r).Counts();
            if (f.WorthALook > 0 || failOn.Equals("unusual", StringComparison.OrdinalIgnoreCase) && f.Unusual > 0)
                return PCPorter.Core.Cli.ExitCodes.FindingsFound;
        }
        return outcome == ScanOutcome.Ok ? PCPorter.Core.Cli.ExitCodes.Ok : PCPorter.Core.Cli.ExitCodes.Partial;
    }

    /// <summary>Deletes a case folder this run created (never through a link: CaseFolder refused those). False if anything is left.</summary>
    static bool TryDelete(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, true); return true; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
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
