using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class RunningJobsTests
{
    /// <summary>A job that, once cancelled, takes <paramref name="cleanUp"/> to tidy up and then ends.</summary>
    static Task<int> Job(CancellationToken ct, TimeSpan cleanUp, List<string> log) => Task.Run(async () =>
    {
        try { await Task.Delay(Timeout.Infinite, ct); return 0; }
        finally { await Task.Delay(cleanUp); lock (log) log.Add("cleaned up"); }
    });

    [Fact]
    public async Task Stop_cancels_and_waits_for_the_clean_up()
    {
        var jobs = new RunningJobs();
        var log = new List<string>();
        using var cts = new CancellationTokenSource();
        var task = jobs.Track(cts, Job(cts.Token, TimeSpan.FromMilliseconds(200), log));
        Assert.True(jobs.Any);

        Assert.True(await jobs.StopAllAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(["cleaned up"], log);
        Assert.True(task.IsCanceled);
        Assert.False(jobs.Any);
    }

    [Fact]
    public async Task Stop_gives_up_after_the_timeout()
    {
        var jobs = new RunningJobs();
        using var cts = new CancellationTokenSource();
        _ = jobs.Track(cts, Job(cts.Token, TimeSpan.FromSeconds(5), []));
        Assert.False(await jobs.StopAllAsync(TimeSpan.FromMilliseconds(100)));
    }

    [Fact]
    public void Blocking_stop_for_log_off()
    {
        var jobs = new RunningJobs();
        var log = new List<string>();
        using var cts = new CancellationTokenSource();
        _ = jobs.Track(cts, Job(cts.Token, TimeSpan.FromMilliseconds(100), log));
        Assert.True(jobs.StopAll(TimeSpan.FromSeconds(10)));
        Assert.Equal(["cleaned up"], log);
    }

    [Fact]
    public async Task Nothing_running_stops_at_once()
    {
        var jobs = new RunningJobs();
        Assert.False(jobs.Any);
        Assert.True(await jobs.StopAllAsync(TimeSpan.Zero));
        using var cts = new CancellationTokenSource();
        await jobs.Track(cts, Task.FromResult(1));
        Assert.False(jobs.Any);
    }
}
