using System.Diagnostics;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;

namespace PCPorter.Collectors;

/// <param name="Status">Set on the "finished" report for a collector; null on the "started" report.</param>
public sealed record ScanProgress(string Collector, int Step, int Total, string Message, CollectorStatus? Status = null, int Items = 0);

public sealed record CollectorRun(string Collector, CollectorStatus Status, int Items, long Ms, string? Message, CollectorOutput? Output);

public sealed record ScanRunResult(IReadOnlyList<CollectorRun> Runs)
{
    public bool AnyFailed => Runs.Any(r => r.Status is CollectorStatus.Failed or CollectorStatus.TimedOut);
    public bool AnyPartial => Runs.Any(r => r.Status is CollectorStatus.Partial);
    public bool Cancelled => Runs.Any(r => r.Status == CollectorStatus.Cancelled);
    public string Overall => Cancelled ? "cancelled" : AnyFailed || AnyPartial ? "partial" : "ok";
}

/// <summary>
/// Runs collectors one after another. A failing collector is recorded and the rest still run. Only the user's
/// cancellation counts as "cancelled"; a collector that runs past its time limit is "timed out". Error text is redacted.
/// </summary>
public sealed class ScanRunner
{
    readonly IReadOnlyList<ICollector> _collectors;
    readonly TimeSpan _limit;

    public ScanRunner(IReadOnlyList<ICollector> collectors, TimeSpan? perCollectorLimit = null)
    {
        var dupName = collectors.GroupBy(c => c.Name).FirstOrDefault(g => g.Count() > 1);
        if (dupName is not null) throw new ArgumentException($"Two collectors are both named '{dupName.Key}'.");
        _collectors = collectors;
        _limit = perCollectorLimit ?? TimeSpan.FromMinutes(10);
    }

    public ScanRunResult Run(CollectorContext context, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        var runs = new List<CollectorRun>();
        for (int i = 0; i < _collectors.Count; i++)
        {
            var c = _collectors[i];
            if (ct.IsCancellationRequested)
            {
                runs.Add(new CollectorRun(c.Name, CollectorStatus.Cancelled, 0, 0, "Cancelled before it started.", null));
                continue;
            }
            progress?.Report(new ScanProgress(c.Name, i + 1, _collectors.Count, $"Step {i + 1} of {_collectors.Count}: {c.Name}"));
            var sw = Stopwatch.StartNew();
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limit.CancelAfter(_limit);
            CollectorRun run;
            try
            {
                var output = c.Run(context, limit.Token);
                var notes = output.Notes.Count == 0 ? null : Redactor.Redact(string.Join(" ", output.Notes));
                // Collectors that watch the token return "Cancelled" themselves; only the user's token makes that a cancel.
                if (output.Status == CollectorStatus.Cancelled && !ct.IsCancellationRequested)
                {
                    bool timedOut = limit.IsCancellationRequested;
                    context.Warnings.Add(timedOut ? TimedOutWarning(c.Name) : $"{c.Name} stopped before it finished.");
                    output = output with { Status = timedOut ? CollectorStatus.TimedOut : CollectorStatus.Failed };
                    notes = string.Join(" ", new[] { timedOut ? "Took too long and was stopped." : "Stopped before it finished.", notes }.Where(n => n is not null));
                }
                run = new CollectorRun(c.Name, output.Status, output.Items.Count, sw.ElapsedMilliseconds, notes, output);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                run = new CollectorRun(c.Name, CollectorStatus.Cancelled, 0, sw.ElapsedMilliseconds, "Cancelled.", null);
            }
            catch (OperationCanceledException) when (limit.IsCancellationRequested)
            {
                context.Warnings.Add(TimedOutWarning(c.Name));
                run = new CollectorRun(c.Name, CollectorStatus.TimedOut, 0, sw.ElapsedMilliseconds, "Took too long and was stopped.", null);
            }
            catch (Exception ex)
            {
                context.Warnings.Add($"{c.Name} stopped: {Redactor.Redact(ex.Message)}");
                run = new CollectorRun(c.Name, CollectorStatus.Failed, 0, sw.ElapsedMilliseconds, Redactor.Redact($"{ex.GetType().Name}: {ex.Message}"), null);
            }
            runs.Add(run);
            progress?.Report(new ScanProgress(c.Name, i + 1, _collectors.Count, $"{c.Name}: {run.Status} ({run.Items} found)", run.Status, run.Items));
        }
        return new ScanRunResult(runs);
    }

    string TimedOutWarning(string name) =>
        _limit.TotalMinutes >= 1 ? $"{name} took longer than {_limit.TotalMinutes:0} minutes and was stopped."
            : $"{name} took longer than {_limit.TotalSeconds:0.#} seconds and was stopped.";
}

/// <summary>For offline scans: WMI describes the PC running PCPorter, never the scanned drive, so it is switched off.</summary>
public sealed class OfflineWmiClient : IWmiClient
{
    public WmiResult Query(string ns, string wql, TimeSpan? timeout = null) =>
        WmiResult.Fail(WmiOutcome.InvalidNamespace, "Not available when scanning another PC's drive.");
}
