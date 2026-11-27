using PCPorter.Collectors.Health;

namespace PCPorter.Collectors.Tests.Health;

public class ReadinessScorerTests
{
    const long GB = 1L << 30;

    static readonly ReadinessInput Healthy = new(
        MigrationBytes: 100 * GB, NewFreeBytes: 500 * GB,
        OldArchitecture: "x64", NewArchitecture: "x64",
        ReinstallCandidates: 10, CandidatesWithInstaller: 10,
        OldEditionId: "Professional", NewEditionId: "Professional",
        OldUsesBitLocker: true, OldHyperVEnabled: true, OldRdpHostEnabled: true,
        NewProblemDevices: 0, NewMaxDiskWearPercent: 3, NewBugChecks90Days: 0,
        NewTpm20: true, NewSecureBoot: true, NewActivated: true);

    static int Part(ReadinessResult r, string name) => r.Parts.Single(p => p.Name == name).Points;

    [Fact]
    public void Identical_healthy_pcs_score_100()
    {
        var r = ReadinessScorer.Score(Healthy);
        Assert.Equal(100, r.Total);
        Assert.Empty(r.Blockers);
        Assert.Empty(r.Warnings);
        Assert.Equal(100, r.Parts.Sum(p => p.Max));
    }

    [Fact]
    public void Half_of_ten_apps_rounds_away_from_zero_to_13()
    {
        var r = ReadinessScorer.Score(Healthy with { CandidatesWithInstaller = 5 });
        Assert.Equal(13, Part(r, "Apps"));
        Assert.Equal(88, r.Total);
    }

    [Fact]
    public void Exactly_1_0x_space_is_zero_points_without_blocker()
    {
        var r = ReadinessScorer.Score(Healthy with { MigrationBytes = 100, NewFreeBytes = 100 });
        Assert.Equal(0, Part(r, "Space"));
        Assert.Empty(r.Blockers);
        Assert.Equal(75, r.Total);
    }

    [Fact]
    public void Exactly_1_2x_space_is_full_points()
    {
        Assert.Equal(25, Part(ReadinessScorer.Score(Healthy with { MigrationBytes = 100, NewFreeBytes = 120 }), "Space"));
    }

    [Fact]
    public void Space_is_linear_between_1_0x_and_1_2x()
    {
        Assert.Equal(13, Part(ReadinessScorer.Score(Healthy with { MigrationBytes = 100, NewFreeBytes = 110 }), "Space"));  // 12.5 => 13
        Assert.Equal(5, Part(ReadinessScorer.Score(Healthy with { MigrationBytes = 100, NewFreeBytes = 104 }), "Space"));
    }

    [Fact]
    public void Not_enough_space_is_a_blocker_and_caps_at_59()
    {
        var r = ReadinessScorer.Score(Healthy with { MigrationBytes = 100, NewFreeBytes = 99 });
        Assert.Equal(0, Part(r, "Space"));
        Assert.Single(r.Blockers);
        Assert.True(r.Total <= 59);
        Assert.Equal(59, r.Total);   // 75 capped
    }

    [Fact]
    public void Pro_to_home_with_bitlocker_used_loses_5()
    {
        var r = ReadinessScorer.Score(Healthy with { NewEditionId = "Core", OldHyperVEnabled = false, OldRdpHostEnabled = false });
        Assert.Equal(10, Part(r, "Edition"));
        Assert.Single(r.Warnings, w => w.Contains("BitLocker", StringComparison.Ordinal));
    }

    [Fact]
    public void Pro_to_home_losing_bitlocker_hyperv_and_rdp()
    {
        Assert.Equal(0, Part(ReadinessScorer.Score(Healthy with { NewEditionId = "CoreSingleLanguage" }), "Edition"));
    }

    [Fact]
    public void Home_to_home_and_pro_to_pro_keep_full_edition_points()
    {
        Assert.Equal(15, Part(ReadinessScorer.Score(Healthy with { OldEditionId = "Core", NewEditionId = "Core" }), "Edition"));
        Assert.Equal(15, Part(ReadinessScorer.Score(Healthy with { OldEditionId = "Enterprise", NewEditionId = "Professional" }), "Edition"));
    }

    [Fact]
    public void X64_to_arm64_is_5_with_warning()
    {
        var r = ReadinessScorer.Score(Healthy with { NewArchitecture = "arm64" });
        Assert.Equal(5, Part(r, "Architecture"));
        Assert.Single(r.Warnings);
    }

    [Fact]
    public void Arm64_to_x64_is_15_with_note()
    {
        var r = ReadinessScorer.Score(Healthy with { OldArchitecture = "arm64" });
        Assert.Equal(15, Part(r, "Architecture"));
        Assert.Empty(r.Warnings);
        Assert.Contains(r.Notes, n => n.Contains("ARM", StringComparison.Ordinal));
    }

    [Fact]
    public void All_null_offline_profile_is_never_penalised()
    {
        var input = ReadinessInput.FromProfiles(new PcProfile(), new PcProfile(), null, null, 0, 0);
        var r = ReadinessScorer.Score(input);
        Assert.Equal(100, r.Total);
        Assert.Empty(r.Blockers);
        Assert.Empty(r.Warnings);
        Assert.NotEmpty(r.Notes);
    }

    [Fact]
    public void Zero_reinstall_candidates_is_full_app_points()
    {
        Assert.Equal(25, Part(ReadinessScorer.Score(Healthy with { ReinstallCandidates = 0, CandidatesWithInstaller = 0 }), "Apps"));
    }

    [Fact]
    public void Health_penalties_on_new_pc()
    {
        Assert.Equal(7, Part(ReadinessScorer.Score(Healthy with { NewProblemDevices = 2 }), "Health"));
        var amber = ReadinessScorer.Score(Healthy with { NewMaxDiskWearPercent = 80 });
        Assert.Equal(6, Part(amber, "Health"));
        Assert.Contains(amber.Warnings, w => w.StartsWith("Amber", StringComparison.Ordinal));
        var red = ReadinessScorer.Score(Healthy with { NewMaxDiskWearPercent = 100 });
        Assert.Equal(6, Part(red, "Health"));
        Assert.Contains(red.Warnings, w => w.StartsWith("Red", StringComparison.Ordinal));
        Assert.Equal(0, Part(ReadinessScorer.Score(Healthy with { NewProblemDevices = 1, NewMaxDiskWearPercent = 100, NewBugChecks90Days = 1 }), "Health"));
    }

    [Fact]
    public void Security_points_and_unknown_is_full()
    {
        Assert.Equal(0, Part(ReadinessScorer.Score(Healthy with { NewTpm20 = false, NewSecureBoot = false, NewActivated = false }), "Security"));
        Assert.Equal(6, Part(ReadinessScorer.Score(Healthy with { NewTpm20 = false }), "Security"));
        Assert.Equal(10, Part(ReadinessScorer.Score(Healthy with { NewTpm20 = null, NewSecureBoot = null, NewActivated = null }), "Security"));
    }

    [Fact]
    public void From_profiles_maps_old_and_new_facts()
    {
        var oldPc = new PcProfile { Architecture = "x64", EditionId = "Professional", BitLocker = [new BitLockerVolume("C:", "on")], HyperVEnabled = false, RdpEnabled = false };
        var newPc = new PcProfile
        {
            Architecture = "x64", EditionId = "Core", TpmVersion = "2.0", SecureBoot = true, Activated = true, ProblemDevices = [],
            PhysicalDisks = [new PhysicalDiskInfo("0", "d", "SSD", "NVMe", 1, "Healthy", 85, null, null), new PhysicalDiskInfo("1", "e", "HDD", "SATA", 1, null, null, null, null)],
        };
        var i = ReadinessInput.FromProfiles(oldPc, newPc, 100, 200, 4, 4);
        Assert.True(i.OldUsesBitLocker);
        Assert.Equal(85, i.NewMaxDiskWearPercent);
        Assert.True(i.NewTpm20);
        var r = ReadinessScorer.Score(i);
        Assert.Equal(25 + 15 + 25 + 10 + 6 + 10, r.Total);
    }
}
