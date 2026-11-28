using PCPorter.Collectors;
using PCPorter.Collectors.Health;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Security;

namespace PCPorter.Reports;

/// <summary>How much one item needs the owner. Report labels, banner counts, the verdict, the CLI and the app all use this.</summary>
public enum Level { Ok, Note, Unusual, WorthALook, FixThis }

/// <summary>Counts in report wording. <see cref="WorthALook"/> includes "Fix this" items.</summary>
public sealed record FindingCounts(int WorthALook, int Unusual, int FixThis = 0);

/// <summary>
/// The ONE place that decides each item's <see cref="Level"/>. The report renders a row per assessed item with the label
/// for its level, and the banner counts the same items, so labels and counts cannot disagree (a regression invariant
/// test checks this on every rendered report).
/// </summary>
public sealed class Assessment
{
    public required PcProfile? Profile { get; init; }
    public required IReadOnlyList<AvProduct> Antivirus { get; init; }
    public required IReadOnlyList<AvProduct> ActiveAntivirus { get; init; }
    /// <summary>True when antivirus state could be read (live scans): only then can "no antivirus" be said.</summary>
    public required bool AntivirusKnown { get; init; }
    public required IReadOnlyList<PostureCheck> Posture { get; init; }
    public required IReadOnlyList<PersistenceItem> Startup { get; init; }
    public required int HiddenStartup { get; init; }
    /// <summary>Kinds of output that were produced ("persistence", "apps"...): "none found" is only said when the check ran.</summary>
    public required IReadOnlySet<string> Ran { get; init; }
    /// <summary>Kinds whose check was stopped part-way (cancelled, timed out): their lists hold only what was found so far.</summary>
    public required IReadOnlySet<string> Unfinished { get; init; }

    /// <summary>
    /// True when the scan was stopped or a check failed or ran out of time: the report then never claims a clean bill of
    /// health ("Incomplete check" instead of "Looks good" / "Mostly fine"). A check that only partly read its data is not
    /// enough for this; it gets the "parts we could check" wording.
    /// </summary>
    public static bool IsIncomplete(ScanRunResult run) => run.Cancelled || run.AnyFailed;

    public static Assessment Of(ScanJobResult r)
    {
        var items = r.Run.Runs.Where(x => x.Output is not null).SelectMany(x => x.Output!.Items).ToList();
        var av = items.OfType<AvProduct>().ToList();
        return new Assessment
        {
            Profile = items.OfType<PcProfile>().FirstOrDefault(),
            Antivirus = av,
            ActiveAntivirus = av.Where(a => a.State == WscState.On && a.Roles.Contains("antivirus", StringComparer.OrdinalIgnoreCase)).ToList(),
            AntivirusKnown = !r.Offline && av.Any(a => a.State is not null),
            Posture = items.OfType<PostureCheck>().ToList(),
            Startup = items.OfType<PersistenceItem>().Where(p => p.Severity != Severity.Hidden).ToList(),
            HiddenStartup = items.OfType<PersistenceItem>().Count(p => p.Severity == Severity.Hidden),
            Ran = r.Run.Runs.Where(x => x.Output is not null && x.Status is CollectorStatus.Ok or CollectorStatus.Partial)
                .Select(x => x.Output!.Kind).ToHashSet(StringComparer.OrdinalIgnoreCase),
            Unfinished = r.Run.Runs.Where(x => x.Output is not null && x.Status is CollectorStatus.Cancelled or CollectorStatus.TimedOut or CollectorStatus.Failed)
                .Select(x => x.Output!.Kind).ToHashSet(StringComparer.OrdinalIgnoreCase),
        };
    }

    // ---- per-item decisions ----
    public bool NoAntivirus => AntivirusKnown && ActiveAntivirus.Count == 0;
    public static Level OfStartup(PersistenceItem s) => s.Severity switch
    {
        Severity.High => s.Disabled ? Level.Unusual : Level.WorthALook,   // turned off: does not run, but still unusual
        Severity.Medium => Level.Unusual,
        _ => Level.Ok,
    };
    public static Level OfPosture(PostureCheck p) => p.Status switch
    {
        PostureStatus.Risk => Level.FixThis,
        PostureStatus.Attention => Level.Unusual,
        PostureStatus.Good => Level.Ok,
        _ => Level.Note,   // Unknown, NotApplicable
    };

    /// <summary>
    /// A posture row's level in this scan. A summary row whose problems are listed one by one (forced browser
    /// extensions) is only a Note: the individual rows carry the level, so two extensions count as two, not three.
    /// </summary>
    public Level LevelOf(PostureCheck p) =>
        p.Id == PostureIds.BrowserExtensions && p.Status == PostureStatus.Attention
            && Posture.Any(c => c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal))
            ? Level.Note
            : OfPosture(p);
    public static bool DiskNeedsCare(PhysicalDiskInfo d) =>
        d.Health is { } hs && !hs.Equals("Healthy", StringComparison.OrdinalIgnoreCase) || d.WearPercent >= 90;
    public static Level OfDisk(PhysicalDiskInfo d) => DiskNeedsCare(d) ? Level.FixThis : Level.Ok;
    public static Level OfFreeSpace(double percentFree) => percentFree < 10 ? Level.Unusual : Level.Ok;
    public static Level OfBattery(int healthPercent) => healthPercent < 60 ? Level.Unusual : Level.Ok;
    public static Level OfCrashes(CrashSummary c) => c.BugChecks90Days > 2 ? Level.WorthALook : c.BugChecks90Days > 0 || c.UnexpectedShutdowns > 0 ? Level.Note : Level.Ok;
    /// <summary>Null = not shown (22: turned off on purpose in Device Manager).</summary>
    public static Level? OfDevice(ProblemDevice d) => d.ErrorCode switch { 22 => null, 24 or 45 => Level.Note, _ => Level.Unusual };

    /// <summary>Every assessed item's level, in the order the report shows them.</summary>
    public IEnumerable<Level> Levels()
    {
        if (NoAntivirus) yield return Level.FixThis;
        foreach (var p in Posture) yield return LevelOf(p);
        foreach (var s in Startup) yield return OfStartup(s);
        if (Profile is not { } pc) yield break;
        foreach (var d in pc.PhysicalDisks ?? []) yield return OfDisk(d);
        foreach (var l in pc.LogicalDisks ?? [])
            if (l.SizeBytes is > 0 && l.FreeBytes is { } free) yield return OfFreeSpace(free * 100.0 / l.SizeBytes.Value);
        foreach (var b in pc.Batteries ?? []) if (b.HealthPercent is { } hp) yield return OfBattery(hp);
        if (pc.Crashes is { } c) yield return OfCrashes(c);
        foreach (var d in pc.ProblemDevices ?? []) if (OfDevice(d) is { } lv) yield return lv;
    }

    public FindingCounts Counts()
    {
        int fix = 0, look = 0, unusual = 0;
        foreach (var l in Levels())
            switch (l) { case Level.FixThis: fix++; break; case Level.WorthALook: look++; break; case Level.Unusual: unusual++; break; }
        return new FindingCounts(fix + look, unusual, fix);
    }

    /// <summary>Worst level present: decides the verdict.</summary>
    public Level Worst() => Levels().DefaultIfEmpty(Level.Ok).Max();

    public static string Label(Level l) => l switch
    {
        Level.FixThis => "Fix this", Level.WorthALook => "Worth a look", Level.Unusual => "Unusual", Level.Note => "Note", _ => "OK",
    };
}
