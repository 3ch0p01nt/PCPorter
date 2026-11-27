namespace PCPorter.Collectors.Health;

/// <summary>
/// Everything the readiness score needs. Null = unknown, which always scores full points (never a penalty).
/// Health and security facts are about the NEW PC only.
/// </summary>
public sealed record ReadinessInput(
    long? MigrationBytes,
    long? NewFreeBytes,
    string? OldArchitecture,
    string? NewArchitecture,
    int ReinstallCandidates,
    int CandidatesWithInstaller,
    string? OldEditionId,
    string? NewEditionId,
    bool? OldUsesBitLocker,
    bool? OldHyperVEnabled,
    bool? OldRdpHostEnabled,
    int? NewProblemDevices,
    int? NewMaxDiskWearPercent,
    int? NewBugChecks90Days,
    bool? NewTpm20,
    bool? NewSecureBoot,
    bool? NewActivated)
{
    /// <summary>Builds the input from two profiles (old = the PC being replaced, new = the PC being set up).</summary>
    public static ReadinessInput FromProfiles(PcProfile? oldPc, PcProfile? newPc, long? migrationBytes, long? newFreeBytes,
        int reinstallCandidates, int candidatesWithInstaller) => new(
        migrationBytes, newFreeBytes, oldPc?.Architecture, newPc?.Architecture, reinstallCandidates, candidatesWithInstaller,
        oldPc?.EditionId, newPc?.EditionId,
        oldPc?.BitLocker is { } bl ? bl.Any(v => v.Protection == "on") : null,
        oldPc?.HyperVEnabled, oldPc?.RdpEnabled,
        newPc?.ProblemDevices?.Count,
        newPc?.PhysicalDisks?.Where(d => d.WearPercent is not null).Select(d => d.WearPercent).Max(),
        newPc?.Crashes?.BugChecks90Days,
        newPc?.TpmVersion is { } t ? t.StartsWith("2.", StringComparison.Ordinal) : newPc?.TpmPresent == false ? false : null,
        newPc?.SecureBoot, newPc?.Activated);
}

public sealed record ReadinessPart(string Name, int Points, int Max);

public sealed record ReadinessResult(int Total, IReadOnlyList<ReadinessPart> Parts, IReadOnlyList<string> Blockers,
    IReadOnlyList<string> Warnings, IReadOnlyList<string> Notes);

/// <summary>Readiness score v2 (pure). Weights: space 25, architecture 15, apps 25, edition 15, health 10, security 10.</summary>
public static class ReadinessScorer
{
    public const int BlockerCap = 59;

    public static ReadinessResult Score(ReadinessInput i)
    {
        var blockers = new List<string>();
        var warnings = new List<string>();
        var notes = new List<string>();
        var parts = new List<ReadinessPart>
        {
            new("Space", Round(Space(i, blockers, notes)), 25),
            new("Architecture", Round(Architecture(i, warnings, notes)), 15),
            new("Apps", Round(Apps(i, notes)), 25),
            new("Edition", Round(Edition(i, warnings)), 15),
            new("Health", Round(Health(i, warnings)), 10),
            new("Security", Round(Security(i, notes)), 10),
        };
        var total = parts.Sum(p => p.Points);
        if (blockers.Count > 0) total = Math.Min(total, BlockerCap);
        return new ReadinessResult(total, parts, blockers, warnings, notes);
    }

    static int Round(decimal d) => (int)Math.Round(d, MidpointRounding.AwayFromZero);

    /// <summary>&lt; 1.0x = 0 + blocker; 1.0x..1.2x linear 0..25; &gt;= 1.2x = 25.</summary>
    static decimal Space(ReadinessInput i, List<string> blockers, List<string> notes)
    {
        if (i.MigrationBytes is null || i.NewFreeBytes is null) { notes.Add("Free space on the new PC or the size to move is unknown."); return 25; }
        if (i.MigrationBytes <= 0) return 25;
        var ratio = (decimal)i.NewFreeBytes.Value / i.MigrationBytes.Value;
        if (ratio < 1.0m) { blockers.Add("The new PC does not have enough free space for everything you chose to move."); return 0; }
        if (ratio >= 1.2m) return 25;
        return 25m * (ratio - 1.0m) / 0.2m;
    }

    static decimal Architecture(ReadinessInput i, List<string> warnings, List<string> notes)
    {
        var o = i.OldArchitecture?.ToLowerInvariant();
        var n = i.NewArchitecture?.ToLowerInvariant();
        if (o is null || n is null || o == n) return 15;
        if (n == "arm64")
        {
            warnings.Add("The new PC uses an ARM processor: some older apps and drivers (antivirus, VPN, printers, games with anti-cheat) may not work.");
            return 5;
        }
        if (o == "arm64") notes.Add("Moving from an ARM PC to an x64 PC: reinstall the x64 versions of your apps.");
        return 15;
    }

    static decimal Apps(ReadinessInput i, List<string> notes)
    {
        if (i.ReinstallCandidates <= 0) return 25;
        var with = Math.Clamp(i.CandidatesWithInstaller, 0, i.ReinstallCandidates);
        if (with < i.ReinstallCandidates) notes.Add($"{i.ReinstallCandidates - with} of {i.ReinstallCandidates} apps have no known installer.");
        return 25m * with / i.ReinstallCandidates;
    }

    static bool IsProLike(string? e) => e is not null &&
        (e.StartsWith("Professional", StringComparison.OrdinalIgnoreCase) || e.StartsWith("Enterprise", StringComparison.OrdinalIgnoreCase)
         || e.StartsWith("Education", StringComparison.OrdinalIgnoreCase));

    static decimal Edition(ReadinessInput i, List<string> warnings)
    {
        if (!IsProLike(i.OldEditionId) || !HiveProfile.IsHome(i.NewEditionId)) return 15;
        decimal points = 15;
        if (i.OldUsesBitLocker == true) { points -= 5; warnings.Add("The new PC runs Windows Home: BitLocker drive encryption is not available (Home has Device Encryption only on some PCs)."); }
        if (i.OldHyperVEnabled == true) { points -= 5; warnings.Add("The new PC runs Windows Home: Hyper-V virtual machines are not available."); }
        if (i.OldRdpHostEnabled == true) { points -= 5; warnings.Add("The new PC runs Windows Home: other PCs cannot connect to it with Remote Desktop."); }
        return points;
    }

    /// <summary>New PC only: devices with errors -3, disk wear &gt;= 80% -4 (amber) / &gt;= 100% red, bugchecks in 90 days -3.</summary>
    static decimal Health(ReadinessInput i, List<string> warnings)
    {
        decimal points = 10;
        if (i.NewProblemDevices is > 0) { points -= 3; warnings.Add($"The new PC has {i.NewProblemDevices} device(s) with driver problems."); }
        if (i.NewMaxDiskWearPercent is >= 100) { points -= 4; warnings.Add("Red: a disk in the new PC has used all of its rated life."); }
        else if (i.NewMaxDiskWearPercent is >= 80) { points -= 4; warnings.Add("Amber: a disk in the new PC has used 80% or more of its rated life."); }
        if (i.NewBugChecks90Days is > 0) { points -= 3; warnings.Add($"The new PC crashed (blue screen) {i.NewBugChecks90Days} time(s) in the last 90 days."); }
        return points;
    }

    /// <summary>New PC only: TPM 2.0 = 4, Secure Boot = 3, activated = 3. Unknown = full points.</summary>
    static decimal Security(ReadinessInput i, List<string> notes)
    {
        if (i.NewTpm20 is null || i.NewSecureBoot is null || i.NewActivated is null) notes.Add("Some security facts of the new PC are unknown and were not counted against it.");
        return (i.NewTpm20 == false ? 0 : 4) + (i.NewSecureBoot == false ? 0 : 3) + (i.NewActivated == false ? 0 : 3);
    }
}
