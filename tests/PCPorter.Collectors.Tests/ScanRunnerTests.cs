using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests;

public class ScanRunnerTests
{
    sealed record Item(string ItemKey) : IScanItem;

    sealed class Fake(string name, Func<CancellationToken, CollectorOutput> run) : ICollector
    {
        public string Name => name;
        public int Calls { get; private set; }
        public CollectorOutput Run(CollectorContext context, CancellationToken ct) { Calls++; return run(ct); }
    }

    sealed class SyncProgress : IProgress<ScanProgress> { public List<ScanProgress> Messages { get; } = []; public void Report(ScanProgress v) => Messages.Add(v); }

    static CollectorContext Ctx() => new(new FakeSystemSource(@"C:\"), new FakeWmiClient(), new FakeProcessRunner((_, _) => new(0, "", false)),
        new NoSignatureChecker(), Path.GetTempPath(), new List<string>());

    static CollectorOutput Ok(int n) => new("k", Enumerable.Range(0, n).Select(i => (IScanItem)new Item($"i{i}")).ToList(), []);

    [Fact]
    public void A_throwing_collector_is_recorded_and_the_rest_still_run()
    {
        var after = new Fake("after", _ => Ok(2));
        var ctx = Ctx();
        var r = new ScanRunner([new Fake("first", _ => Ok(1)), new Fake("boom", _ => throw new IOException("disk said password=hunter2")), after]).Run(ctx);
        Assert.Equal([CollectorStatus.Ok, CollectorStatus.Failed, CollectorStatus.Ok], r.Runs.Select(x => x.Status));
        Assert.Equal(1, after.Calls);
        Assert.True(r.AnyFailed);
        Assert.DoesNotContain("hunter2", r.Runs[1].Message);                // redacted
        Assert.Single(ctx.Warnings);
    }

    [Fact]
    public void Cancelling_marks_the_rest_cancelled_not_failed()
    {
        using var cts = new CancellationTokenSource();
        var third = new Fake("third", _ => Ok(1));
        var r = new ScanRunner([new Fake("one", _ => Ok(1)), new Fake("two", ct => { cts.Cancel(); ct.ThrowIfCancellationRequested(); return Ok(1); }), third])
            .Run(Ctx(), ct: cts.Token);
        Assert.Equal([CollectorStatus.Ok, CollectorStatus.Cancelled, CollectorStatus.Cancelled], r.Runs.Select(x => x.Status));
        Assert.Equal(0, third.Calls);
        Assert.False(r.AnyFailed);
        Assert.True(r.Cancelled);
    }

    [Fact]
    public void Skipped_offline_is_not_a_failure_and_progress_is_in_order()
    {
        var p = new SyncProgress();
        var r = new ScanRunner([new Fake("A", _ => Ok(3)), new Fake("B", _ => new CollectorOutput("b", [], ["live only"], CollectorStatus.SkippedOffline))]).Run(Ctx(), p);
        Assert.False(r.AnyFailed);
        Assert.Equal(["Step 1 of 2: A", "A: Ok (3 found)", "Step 2 of 2: B", "B: SkippedOffline (0 found)"], p.Messages.Select(m => m.Message));
        Assert.Equal([null, CollectorStatus.Ok, null, CollectorStatus.SkippedOffline], p.Messages.Select(m => m.Status));
        Assert.Equal(3, r.Runs[0].Items);
    }

    [Fact]
    public void Internal_cancellation_without_user_cancel_is_a_failure_not_a_cancel()
    {
        var after = new Fake("after", _ => Ok(1));
        var r = new ScanRunner([new Fake("inner timeout", _ => throw new OperationCanceledException()), after]).Run(Ctx());
        Assert.Equal(CollectorStatus.Failed, r.Runs[0].Status);
        Assert.Equal(1, after.Calls);
        Assert.False(r.Cancelled);
    }

    [Fact]
    public void A_collector_past_its_time_limit_is_timed_out_and_the_rest_run()
    {
        var after = new Fake("after", _ => Ok(1));
        var slow = new Fake("slow", ct => { Task.Delay(Timeout.Infinite, ct).Wait(ct); return Ok(1); });
        var r = new ScanRunner([slow, after], TimeSpan.FromMilliseconds(200)).Run(Ctx());
        Assert.Equal([CollectorStatus.TimedOut, CollectorStatus.Ok], r.Runs.Select(x => x.Status));
        Assert.True(r.AnyFailed);
        Assert.Equal("partial", r.Overall);
    }

    [Fact]
    public void Warnings_are_redacted_and_duplicate_names_are_refused()
    {
        var ctx = Ctx();
        new ScanRunner([new Fake("boom", _ => throw new IOException("token=abc123"))]).Run(ctx);
        Assert.DoesNotContain("abc123", ctx.Warnings[0]);
        Assert.Throws<ArgumentException>(() => new ScanRunner([new Fake("x", _ => Ok(0)), new Fake("x", _ => Ok(0))]));
    }

    [Fact]
    public void Partial_makes_the_scan_partial() =>
        Assert.Equal("partial", new ScanRunner([new Fake("p", _ => new CollectorOutput("k", [], [], CollectorStatus.Partial))]).Run(Ctx()).Overall);

    [Fact]
    public void Offline_wmi_never_answers() =>
        Assert.Equal(WmiOutcome.InvalidNamespace, new OfflineWmiClient().Query(@"root\cimv2", "SELECT * FROM Win32_OperatingSystem").Outcome);
}
