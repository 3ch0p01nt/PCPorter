using PCPorter.Collectors.Posture;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Posture;

public class WindowsLifecycleTests
{
    static SupportState At(int build, string edition, int y, int m, int d) =>
        WindowsLifecycle.Evaluate(build, edition, new DateOnly(y, m, d)).State;

    [Theory]
    // Windows 11 24H2 Home/Pro: last day 2026-10-13
    [InlineData(26100, "Professional", 2026, 10, 13, SupportState.EndingSoon)]
    [InlineData(26100, "Professional", 2026, 10, 14, SupportState.Ended)]
    [InlineData(26100, "Core", 2026, 7, 15, SupportState.EndingSoon)]       // 90 days before the end
    [InlineData(26100, "Core", 2026, 7, 14, SupportState.Supported)]
    // Enterprise/Education get +12 months
    [InlineData(26100, "Enterprise", 2026, 10, 14, SupportState.Supported)]
    [InlineData(26100, "Education", 2027, 10, 12, SupportState.EndingSoon)]
    [InlineData(26100, "EnterpriseN", 2027, 10, 13, SupportState.Ended)]
    // Windows 11 23H2
    [InlineData(22631, "Professional", 2025, 11, 11, SupportState.EndingSoon)]
    [InlineData(22631, "Professional", 2025, 11, 12, SupportState.Ended)]
    [InlineData(22631, "Enterprise", 2026, 11, 10, SupportState.EndingSoon)]
    [InlineData(22631, "Enterprise", 2026, 11, 11, SupportState.Ended)]
    // Windows 11 25H2
    [InlineData(26200, "Core", 2026, 11, 26, SupportState.Supported)]
    [InlineData(26200, "Core", 2027, 10, 12, SupportState.EndingSoon)]
    [InlineData(26200, "Core", 2027, 10, 13, SupportState.Ended)]
    // Windows 10 22H2: consumer ESU to 2026-10-13; Enterprise ended 2025-10-14
    [InlineData(19045, "Professional", 2025, 10, 14, SupportState.EndingSoon)]
    [InlineData(19045, "Professional", 2025, 10, 15, SupportState.ExtendedSecurityUpdates)]
    [InlineData(19045, "Core", 2026, 10, 13, SupportState.ExtendedSecurityUpdates)]
    [InlineData(19045, "Core", 2026, 10, 14, SupportState.Ended)]
    [InlineData(19045, "Enterprise", 2025, 10, 15, SupportState.Ended)]
    // Unknowns: unlisted builds, LTSC, server, unrecognised editions
    [InlineData(27000, "Professional", 2026, 11, 26, SupportState.Unknown)]
    [InlineData(17763, "Professional", 2026, 11, 26, SupportState.Unknown)]
    [InlineData(19044, "EnterpriseS", 2026, 11, 26, SupportState.Unknown)]
    [InlineData(26100, "ServerStandard", 2026, 11, 26, SupportState.Unknown)]
    [InlineData(26100, "Mystery", 2026, 11, 26, SupportState.Unknown)]
    public void Edge_dates(int build, string edition, int y, int m, int d, SupportState expected) =>
        Assert.Equal(expected, At(build, edition, y, m, d));

    [Fact]
    public void Build_22000_and_later_is_windows_11()
    {
        Assert.Equal("Windows 10", WindowsLifecycle.ProductForBuild(19045));
        Assert.Equal("Windows 11", WindowsLifecycle.ProductForBuild(22000));
        Assert.All(WindowsLifecycle.Table, e => Assert.Equal(WindowsLifecycle.ProductForBuild(e.Build), e.Product));
        Assert.All(WindowsLifecycle.Table, e => Assert.True(e.EnterpriseEnd >= e.HomeProEnd));
    }

    [Fact]
    public void Missing_build_is_unknown() => Assert.Equal(SupportState.Unknown, WindowsLifecycle.Evaluate(null, "Professional", new(2026, 1, 1)).State);

    static RegSpec Cv(string build, string edition, string? display = null) => RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion", k =>
    {
        k.Str("CurrentBuild", build).Num("UBR", 1234).Str("EditionID", edition);
        if (display is not null) k.Str("DisplayVersion", display);
    });

    [Fact]
    public void Ended_windows_is_critical_risk()
    {
        var c = PT.Check(PT.Offline(Cv("26100", "Professional", "24H2")), PostureIds.WindowsSupport);
        Assert.Equal(PostureStatus.Risk, c.Status);
        Assert.Equal(PostureSeverity.Critical, c.Severity);
        Assert.Contains("Windows 11 24H2", c.Finding);
        Assert.Contains("UBR=1234", c.Evidence);
    }

    [Fact]
    public void Supported_windows_is_good_and_unknown_build_is_unknown()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(Cv("26200", "Core", "25H2")), PostureIds.WindowsSupport).Status);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(Cv("26100", "Enterprise")), PostureIds.WindowsSupport).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(Cv("29999", "Core")), PostureIds.WindowsSupport).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.WindowsSupport).Status);
    }
}
