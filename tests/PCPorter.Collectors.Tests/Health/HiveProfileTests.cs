using PCPorter.Collectors.Health;
using PCPorter.TestKit;
using static PCPorter.Collectors.Tests.Health.TestContexts;

namespace PCPorter.Collectors.Tests.Health;

public class HiveProfileTests
{
    [Theory]
    [InlineData("Windows 10 Enterprise", "Enterprise", 26200, "Windows 11 Enterprise")]
    [InlineData("Windows 10 Pro", "Professional", 22631, "Windows 11 Pro")]
    [InlineData("Windows 10 Home", "Core", 26100, "Windows 11 Home")]
    [InlineData("Windows 10 Home Single Language", "CoreSingleLanguage", 22000, "Windows 11 Home")]
    [InlineData("Windows 10 Pro", "Professional", 19045, "Windows 10 Pro")]
    public void Os_name_uses_build_for_windows_11(string productName, string editionId, int build, string expected) =>
        Assert.Equal(expected, HiveProfile.OsName(productName, editionId, build));

    [Theory]
    [InlineData("AMD64", "x64")]
    [InlineData("ARM64", "arm64")]
    [InlineData("x86", "x86")]
    [InlineData(null, null)]
    public void Architecture_is_normalised(string? raw, string? expected) => Assert.Equal(expected, HiveProfile.NormalizeArch(raw));

    static readonly DateTimeOffset Feature = new(2025, 10, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset First = new(2022, 3, 5, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Second = new(2024, 1, 2, 0, 0, 0, TimeSpan.Zero);

    static (RegSpec Software, RegSpec System) FullPc(uint vmmsStart = 3)
    {
        var sw = RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k
                .Str("ProductName", "Windows 10 Enterprise").Str("EditionID", "Enterprise").Str("DisplayVersion", "25H2")
                .Str("CurrentBuildNumber", "26200").Str("CurrentBuild", "26200").Num("UBR", 7171)
                .Num("InstallDate", (uint)Feature.ToUnixTimeSeconds()))
            .Key(@"Microsoft\Cryptography", k => k.Str("MachineGuid", "00000000-1111-2222-3333-444444444444"))
            .Key(@"Microsoft\Enrollments\{A}", k => k.Str("UPN", "user@example.com"));
        var sys = SystemHive(cs => cs
                .Key(@"Control\Session Manager\Environment", k => k.Str("PROCESSOR_ARCHITECTURE", "AMD64"))
                .Key(@"Control\ComputerName\ComputerName", k => k.Str("ComputerName", "TESTPC"))
                .Key(@"Control\SecureBoot\State", k => k.Num("UEFISecureBootEnabled", 1))
                .Key(@"Control\Terminal Server", k => k.Num("fDenyTSConnections", 0))
                .Key(@"Services\vmms", k => k.Num("Start", vmmsStart))
                .Key(@"Services\Tcpip\Parameters", k => k.Str("Domain", "corp.example.com"))
                .Key($@"Control\Class\{HiveProfile.DisplayClass}\0000", k => k.Str("DriverDesc", "GPU A").QNum("HardwareInformation.qwMemorySize", 8UL << 30))
                .Key($@"Control\Class\{HiveProfile.DisplayClass}\0001", k => k.Str("DriverDesc", "GPU B").Bin("HardwareInformation.MemorySize", 0x00, 0x00, 0x00, 0x20))
                .Key($@"Control\Class\{HiveProfile.DisplayClass}\0002", k => k.Str("DriverDesc", "GPU B").Bin("HardwareInformation.MemorySize", 0x00, 0x00, 0x00, 0x20))   // duplicate ghost
                .Key($@"Control\Class\{HiveProfile.DisplayClass}\Configuration", k => k.Str("DriverDesc", "not an adapter")))
            .Key($"Setup\\Source OS (Updated on {Second:M/d/yyyy} 10:00:00)", k => k.Num("InstallDate", (uint)Second.ToUnixTimeSeconds()))
            .Key($"Setup\\Source OS (Updated on {First:M/d/yyyy} 10:00:00)", k => k.Num("InstallDate", (uint)First.ToUnixTimeSeconds()));
        return (sw, sys);
    }

    [Fact]
    public void Reads_everything_from_hives()
    {
        var (sw, sys) = FullPc();
        var warnings = new List<string>();
        var p = HiveProfile.Read(new FakeSystemSource(@"D:\", sw, sys), warnings);
        Assert.Empty(warnings);
        Assert.Equal("Windows 11 Enterprise", p.OsName);
        Assert.Equal("Enterprise", p.EditionId);
        Assert.False(p.IsHomeEdition);
        Assert.Equal("25H2", p.DisplayVersion);
        Assert.Equal(26200, p.Build);
        Assert.Equal(7171, p.Ubr);
        Assert.Equal(Feature, p.LastFeatureUpdate);
        Assert.Equal(First, p.OriginalInstall);
        Assert.Equal("x64", p.Architecture);
        Assert.Equal("TESTPC", p.ComputerName);
        Assert.Equal("00000000-1111-2222-3333-444444444444", p.MachineGuid);
        Assert.True(p.SecureBoot);
        Assert.True(p.RdpEnabled);
        Assert.True(p.HyperVEnabled);
        Assert.True(p.DomainJoined);
        Assert.True(p.EntraJoined);
        Assert.Equal(2, p.Gpus!.Count);
        Assert.Equal(8L << 30, p.Gpus[0].VramBytes);
        Assert.Equal(0x20000000L, p.Gpus[1].VramBytes);
    }

    [Fact]
    public void Disabled_vmms_means_no_hyper_v()
    {
        var (sw, sys) = FullPc(vmmsStart: 4);
        Assert.False(HiveProfile.Read(new FakeSystemSource(@"D:\", sw, sys), new List<string>()).HyperVEnabled);
    }

    [Fact]
    public void Without_source_os_keys_original_install_is_the_feature_update()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Num("InstallDate", (uint)Feature.ToUnixTimeSeconds()));
        var p = HiveProfile.Read(new FakeSystemSource(@"D:\", sw, SystemHive()), new List<string>());
        Assert.Equal(Feature, p.OriginalInstall);
        Assert.False(p.HyperVEnabled);
        Assert.Null(p.RdpEnabled);
        Assert.Null(p.SecureBoot);
        Assert.Empty(p.Gpus ?? []);
    }

    [Fact]
    public void Missing_hives_give_nulls_not_exceptions()
    {
        var warnings = new List<string>();
        var p = HiveProfile.Read(new FakeSystemSource(@"D:\"), warnings);
        Assert.Null(p.OsName);
        Assert.Null(p.Architecture);
        Assert.Null(p.DomainJoined);
        Assert.Null(p.EntraJoined);
        Assert.Null(p.Gpus);
        Assert.Equal("profile", p.ItemKey);
    }
}
