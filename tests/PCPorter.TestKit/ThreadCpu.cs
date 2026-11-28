using System.Runtime.InteropServices;

namespace PCPorter.TestKit;

/// <summary>
/// Processor time of one piece of work, measured on the thread that runs it (wall clock is unreliable while the suite
/// runs in parallel). Work still busy after <c>cap</c> counts as <c>cap</c>, so a hang fails instead of stalling the suite.
/// An exception from the work is rethrown.
/// </summary>
public static class ThreadCpu
{
    public static TimeSpan Of(Action work, TimeSpan? cap = null)
    {
        var limit = cap ?? TimeSpan.FromSeconds(30);
        var cpu = limit;
        Exception? error = null;
        var t = new Thread(() =>
        {
            var before = Now();
            try { work(); }
            catch (Exception e) { error = e; }
            cpu = Now() - before;
        }) { IsBackground = true };
        t.Start();
        if (!t.Join(limit)) return limit;
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
        return cpu;
    }

    static TimeSpan Now()
    {
        GetThreadTimes(GetCurrentThread(), out _, out _, out var kernel, out var user);
        return TimeSpan.FromTicks(kernel + user);
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetThreadTimes(IntPtr thread, out long creation, out long exit, out long kernel, out long user);
}
