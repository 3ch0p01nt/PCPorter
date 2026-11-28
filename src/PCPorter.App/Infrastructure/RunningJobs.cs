namespace PCPorter.App.Infrastructure;

/// <summary>
/// The jobs running on any page, so closing the window (or logging off) can stop them and wait for their clean-up
/// (work folders with copied browser databases, temporary shadow copies) instead of the process simply ending.
/// </summary>
public sealed class RunningJobs
{
    public static RunningJobs Instance { get; } = new();

    readonly object _lock = new();
    readonly List<(CancellationTokenSource Cts, Task Task)> _jobs = [];

    public bool Any { get { lock (_lock) return _jobs.Any(j => !j.Task.IsCompleted); } }

    /// <summary>Tracks <paramref name="task"/> until it ends; <paramref name="cts"/> stops it.</summary>
    public Task<T> Track<T>(CancellationTokenSource cts, Task<T> task)
    {
        var entry = (cts, (Task)task);
        lock (_lock) _jobs.Add(entry);
        task.ContinueWith(_ => { lock (_lock) _jobs.Remove(entry); }, TaskContinuationOptions.ExecuteSynchronously);
        return task;
    }

    /// <summary>Asks every job to stop and waits for them to end (their own clean-up included). False when the time ran out.</summary>
    public async Task<bool> StopAllAsync(TimeSpan timeout)
    {
        var tasks = CancelAll();
        if (tasks.Length == 0) return true;
        var all = Task.WhenAll(tasks);
        var finished = await Task.WhenAny(all, Task.Delay(timeout)).ConfigureAwait(false) == all;
        _ = all.Exception;   // a job that failed while stopping is logged by its page; never rethrown here
        return finished;
    }

    /// <summary>The blocking form, for log-off (Windows allows only a few seconds and no dialog).</summary>
    public bool StopAll(TimeSpan timeout)
    {
        var tasks = CancelAll();
        if (tasks.Length == 0) return true;
        try { return Task.WaitAll(tasks, timeout); }
        catch (AggregateException) { return true; }   // they ended (some with an error): nothing is left running
    }

    Task[] CancelAll()
    {
        List<(CancellationTokenSource Cts, Task Task)> jobs;
        lock (_lock) jobs = [.. _jobs];
        foreach (var (cts, _) in jobs)
            try { cts.Cancel(); } catch (ObjectDisposedException) { }
        return [.. jobs.Select(j => j.Task)];
    }
}
