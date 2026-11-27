namespace PCPorter.Collectors.Health;

/// <summary>
/// Builds the PC profile: hives (both modes), WMI + display APIs + battery (live only), crash history (both modes).
/// Read-only. Never throws for bad data: problems become warnings and the field stays null.
/// </summary>
/// <param name="monitors">Display-API reader (tests inject a fake); default <see cref="DisplayInfo.Query"/>.</param>
/// <param name="events">Event-log reader (tests inject a fake); default <see cref="CrashHistory.QueryEvents"/>.</param>
public sealed class ProfileCollector(Func<IList<string>, IReadOnlyList<NativeMonitor>>? monitors = null, EventQuery? events = null,
    Func<DateTimeOffset>? clock = null) : ICollector
{
    public const string Kind = "profile";
    public string Name => "PC profile and health";

    public CollectorOutput Run(CollectorContext ctx, CancellationToken ct)
    {
        var notes = new List<string>();
        int warningsBefore = ctx.Warnings.Count;
        var src = ctx.Source;
        PcProfile p;
        try { p = HiveProfile.Read(src, ctx.Warnings); }
        catch (Exception e) { ctx.Warnings.Add($"Profile: hives failed: {e.Message}"); p = new PcProfile(); }
        if (ct.IsCancellationRequested) return new(Kind, [p], notes, CollectorStatus.Cancelled);

        var unknown = new Dictionary<string, string>(p.Unknown, StringComparer.OrdinalIgnoreCase);
        if (src.IsLive)
        {
            try { p = WmiProfile.Apply(p, ctx.Wmi, ctx.Warnings); unknown = new(p.Unknown, StringComparer.OrdinalIgnoreCase); }
            catch (Exception e) { ctx.Warnings.Add($"Profile: WMI failed: {e.Message}"); }
            if (ct.IsCancellationRequested) return new(Kind, [p with { Unknown = unknown }], notes, CollectorStatus.Cancelled);

            try { p = p with { Monitors = WmiProfile.Monitors((monitors ?? DisplayInfo.Query)(ctx.Warnings), ctx.Wmi, ctx.Warnings) }; }
            catch (Exception e) { ctx.Warnings.Add($"Profile: monitors failed: {e.Message}"); }

            try { p = p with { Batteries = BatteryReport.Read(ctx.Processes, ctx.Wmi, ctx.WorkFolder, ctx.Warnings, unknown) }; }
            catch (Exception e) { ctx.Warnings.Add($"Profile: battery failed: {e.Message}"); }
            if (ct.IsCancellationRequested) return new(Kind, [p with { Unknown = unknown }], notes, CollectorStatus.Cancelled);
        }
        else notes.Add("Offline drive: hardware, disks, TPM, activation, monitors and battery come from the running PC only and were skipped.");

        try { p = p with { Crashes = CrashHistory.Read(src, events ?? CrashHistory.QueryEvents, ctx.Warnings, unknown, (clock ?? (() => DateTimeOffset.UtcNow))()) }; }
        catch (Exception e) { ctx.Warnings.Add($"Profile: crash history failed: {e.Message}"); }

        p = p with { Unknown = unknown };
        var status = ctx.Warnings.Count > warningsBefore ? CollectorStatus.Partial : CollectorStatus.Ok;
        return new CollectorOutput(Kind, [p], notes, status);
    }
}
