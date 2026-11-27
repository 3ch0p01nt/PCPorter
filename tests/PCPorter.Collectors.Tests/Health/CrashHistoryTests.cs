using PCPorter.Collectors.Health;
using PCPorter.TestKit;
using Xunit.Abstractions;

namespace PCPorter.Collectors.Tests.Health;

public class CrashHistoryTests : IDisposable
{
    static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-crash").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    [Theory]
    [InlineData("0x0000001e (0xffffffffc0000005, 0x0, 0x0, 0x0)", "0x0000001e")]
    [InlineData("0x00000133(0x1, 0x1e00, 0x0, 0x0)", "0x00000133")]
    [InlineData("  ", null)]
    [InlineData(null, null)]
    public void Bugcheck_code_is_the_first_token(string? data, string? expected) => Assert.Equal(expected, CrashHistory.BugCheckCode(data));

    [Fact]
    public void Only_last_90_days_newest_first()
    {
        var rows = new[]
        {
            new EventRow(Now.AddDays(-10), "0x0000001e (0x1)"),
            new EventRow(Now.AddDays(-91), "0x000000d1 (0x1)"),
            new EventRow(Now.AddDays(-2), "0x00000133 (0x1)"),
        };
        var list = CrashHistory.ParseBugChecks(rows, Now);
        Assert.Equal(["0x00000133", "0x0000001e"], list.Select(c => c.BugCheck));
    }

    [Fact]
    public void Parses_event_xml()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><Provider Name="Microsoft-Windows-WER-SystemErrorReporting"/><EventID>1001</EventID><TimeCreated SystemTime="2026-11-20T08:30:00.1234567Z"/></System>
              <EventData><Data Name="param1">0x0000001e (0xffffffffc0000005, 0x0, 0x0, 0x0)</Data><Data Name="param2">C:\Windows\MEMORY.DMP</Data></EventData>
            </Event>
            """;
        var row = CrashHistory.ParseEventXml(xml)!;
        Assert.Equal(new DateTimeOffset(2026, 11, 20, 8, 30, 0, TimeSpan.Zero), row.When.AddTicks(-(row.When.Ticks % TimeSpan.TicksPerSecond)));
        Assert.StartsWith("0x0000001e", row.FirstData);
        Assert.Null(CrashHistory.ParseEventXml("<broken"));
    }

    [Fact]
    public void Offline_reads_the_old_drives_system_evtx_and_minidumps()
    {
        Directory.CreateDirectory(Path.Combine(_root, @"Windows\System32\winevt\Logs"));
        File.WriteAllText(Path.Combine(_root, @"Windows\System32\winevt\Logs\System.evtx"), "placeholder");
        Directory.CreateDirectory(Path.Combine(_root, @"Windows\Minidump"));
        File.WriteAllText(Path.Combine(_root, @"Windows\Minidump\112026-1.dmp"), "x");
        File.WriteAllText(Path.Combine(_root, @"Windows\Minidump\112126-2.dmp"), "x");
        File.WriteAllText(Path.Combine(_root, @"Windows\Minidump\notes.txt"), "x");

        var calls = new List<(string Log, bool IsFile, string XPath)>();
        IReadOnlyList<EventRow> Fake(string log, bool isFile, string xpath, int max)
        {
            calls.Add((log, isFile, xpath));
            return xpath.Contains("Kernel-Power", StringComparison.Ordinal)
                ? [new EventRow(Now.AddDays(-1), "0"), new EventRow(Now.AddDays(-5), "0")]
                : [new EventRow(Now.AddDays(-3), "0x0000001e (0x1)")];
        }

        var src = new FakeSystemSource(_root);
        var s = CrashHistory.Read(src, Fake, new List<string>(), new Dictionary<string, string>(), Now)!;
        Assert.Equal("0x0000001e", s.BugChecks.Single().BugCheck);
        Assert.Equal(1, s.BugChecks90Days);
        Assert.Equal(2, s.UnexpectedShutdowns);
        Assert.Equal(2, s.MinidumpCount);
        Assert.NotNull(s.NewestMinidump);
        Assert.All(calls, c => Assert.True(c.IsFile));
        Assert.All(calls, c => Assert.Equal(Path.Combine(_root, @"Windows\System32\winevt\Logs\System.evtx"), c.Log));
        Assert.Contains(calls, c => c.XPath.Contains("Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001", StringComparison.Ordinal));
        Assert.Contains(calls, c => c.XPath.Contains("Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41", StringComparison.Ordinal));
    }

    [Fact]
    public void Offline_without_evtx_warns_and_still_counts_minidumps()
    {
        var warnings = new List<string>();
        var s = CrashHistory.Read(new FakeSystemSource(_root), (_, _, _, _) => throw new InvalidOperationException("must not be called"),
            warnings, new Dictionary<string, string>(), Now)!;
        Assert.Single(warnings);
        Assert.Empty(s.BugChecks);
        Assert.Null(s.UnexpectedShutdowns);
        Assert.Equal(0, s.MinidumpCount);
    }

    [Fact]
    public void Unreadable_log_is_unknown_not_a_crash()
    {
        var unknown = new Dictionary<string, string>();
        CrashHistory.Read(new FakeSystemSource(_root, live: true), (_, _, _, _) => throw new UnauthorizedAccessException(), new List<string>(), unknown, Now);
        Assert.Equal(PcProfile.NotElevated, unknown["crashes"]);
    }

    [Fact]
    public void Missing_evtx_file_through_wevtapi_is_an_error_not_a_crash()
    {
        Assert.ThrowsAny<Exception>(() => CrashHistory.QueryEvents(Path.Combine(_root, "none.evtx"), true, CrashHistory.BugCheckXPath, 10));
    }
}

public class CrashHistoryLiveTests(ITestOutputHelper output)
{
    [Fact]
    public void Reads_the_live_system_log_without_admin()
    {
        var bugchecks = CrashHistory.QueryEvents("System", false, CrashHistory.BugCheckXPath, 500);
        var shutdowns = CrashHistory.QueryEvents("System", false, CrashHistory.KernelPowerXPath, 10_000);
        output.WriteLine($"bugchecks90d={bugchecks.Count} kernelPower41={shutdowns.Count}");
        Assert.All(bugchecks, b => Assert.True(b.When > DateTimeOffset.UtcNow.AddDays(-91)));
    }
}
