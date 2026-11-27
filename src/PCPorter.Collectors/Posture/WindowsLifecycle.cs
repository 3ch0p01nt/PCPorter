namespace PCPorter.Collectors.Posture;

public enum EditionTrack { HomePro, EnterpriseEducation, Unknown }

/// <summary>One Windows feature update and the last day it gets security updates.</summary>
public sealed record LifecycleEntry(int Build, string Product, string Version, DateOnly HomeProEnd, DateOnly EnterpriseEnd, DateOnly? EsuEnd = null);

public enum SupportState { Supported, EndingSoon, ExtendedSecurityUpdates, Ended, Unknown }

public sealed record SupportVerdict(SupportState State, LifecycleEntry? Entry, EditionTrack Track, DateOnly? EndDate, string Reason);

/// <summary>Microsoft's support dates for the Windows versions PCPorter recognises (pure data, unit-tested).</summary>
public static class WindowsLifecycle
{
    /// <summary>Days before the end date when we start mentioning it.</summary>
    public const int EndingSoonDays = 90;

    // Lifecycle table as of 2026-11. Update when Microsoft ships a new feature update.
    // Dates are the last Patch Tuesday that still delivers security updates.
    // Windows 10 22H2 ended for every edition on 2025-10-14 (consumer Extended Security Updates run to 2026-10-13).
    // Windows 11 H2 releases: Home/Pro get 24 months, Enterprise/Education get 36 months (+12).
    public static readonly IReadOnlyList<LifecycleEntry> Table =
    [
        new(19044, "Windows 10", "21H2", new(2023, 6, 13), new(2024, 6, 11)),
        new(19045, "Windows 10", "22H2", new(2025, 10, 14), new(2025, 10, 14), EsuEnd: new(2026, 10, 13)),
        new(22000, "Windows 11", "21H2", new(2023, 10, 10), new(2024, 10, 8)),
        new(22621, "Windows 11", "22H2", new(2024, 10, 8), new(2025, 10, 14)),
        new(22631, "Windows 11", "23H2", new(2025, 11, 11), new(2026, 11, 10)),
        new(26100, "Windows 11", "24H2", new(2026, 10, 13), new(2027, 10, 12)),
        new(26200, "Windows 11", "25H2", new(2027, 10, 12), new(2028, 10, 10)),
    ];

    /// <summary>"Windows 11" for build 22000 and later, otherwise "Windows 10" (for NT 10.0 builds).</summary>
    public static string ProductForBuild(int build) => build >= 22000 ? "Windows 11" : "Windows 10";

    /// <summary>Home/Pro or Enterprise/Education from EditionID. LTSC (EnterpriseS), Server and anything unrecognised are Unknown.</summary>
    public static EditionTrack TrackFor(string? editionId)
    {
        if (string.IsNullOrWhiteSpace(editionId)) return EditionTrack.Unknown;
        var e = editionId.Trim();
        bool Is(string prefix) => e.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        if (Is("ServerRdsh")) return EditionTrack.EnterpriseEducation;                     // Enterprise multi-session
        if (Is("EnterpriseS") || Is("IoTEnterpriseS") || Is("Server")) return EditionTrack.Unknown;
        if (Is("Enterprise") || Is("IoTEnterprise") || Is("Education")) return EditionTrack.EnterpriseEducation;
        if (Is("Core") || Is("Professional")) return EditionTrack.HomePro;   // Core* = Home; Professional* = Pro, Pro Education, Pro for Workstations
        return EditionTrack.Unknown;
    }

    public static SupportVerdict Evaluate(int? build, string? editionId, DateOnly today)
    {
        var track = TrackFor(editionId);
        if (build is null) return new(SupportState.Unknown, null, track, null, "The Windows build number could not be read.");
        var entry = Table.FirstOrDefault(t => t.Build == build);
        if (entry is null) return new(SupportState.Unknown, null, track, null, $"Build {build} is not in PCPorter's support table.");
        if (track == EditionTrack.Unknown)
            return new(SupportState.Unknown, entry, track, null, $"Edition '{editionId}' follows its own support dates (for example long-term or server editions).");

        var end = track == EditionTrack.EnterpriseEducation ? entry.EnterpriseEnd : entry.HomeProEnd;
        if (today > end)
        {
            if (track == EditionTrack.HomePro && entry.EsuEnd is { } esu && today <= esu)
                return new(SupportState.ExtendedSecurityUpdates, entry, track, esu, "Regular support ended; paid or free Extended Security Updates are still available.");
            return new(SupportState.Ended, entry, track, end, "Microsoft no longer releases security updates for this version.");
        }
        if (today >= end.AddDays(-EndingSoonDays)) return new(SupportState.EndingSoon, entry, track, end, "Support ends soon.");
        return new(SupportState.Supported, entry, track, end, "This version still gets security updates.");
    }
}
