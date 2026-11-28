using System.IO;
using System.Runtime.InteropServices;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// One PCPorter window per sign-in session. The first start owns a <c>Local\</c> mutex and waits on a named event; a
/// second start sets that event (so the first window comes forward) and exits quietly. <c>Local\</c>, not
/// <c>Global\</c>: another person signed in on the same PC (fast user switching, Remote Desktop) can still use PCPorter.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    public const string DefaultName = "PCPorter-7d1f6a2e";

    readonly Mutex _mutex;
    readonly EventWaitHandle _show;
    readonly RegisteredWaitHandle _wait;

    SingleInstance(Mutex mutex, EventWaitHandle show, Action onShowRequested)
    {
        _mutex = mutex;
        _show = show;
        _wait = ThreadPool.RegisterWaitForSingleObject(show, (_, _) => onShowRequested(), null, Timeout.Infinite, executeOnlyOnce: false);
    }

    /// <summary>
    /// The first start gets an instance (keep it until exit); <paramref name="onShowRequested"/> then runs on a worker
    /// thread each time another start asks. A later start gets null after asking the first one to come forward.
    /// </summary>
    public static SingleInstance? TryClaim(Action onShowRequested, string name = DefaultName)
    {
        var mutexName = $@"Local\{name}";
        var eventName = $@"Local\{name}-show";
        Mutex? mutex = null;
        try
        {
            mutex = new Mutex(true, mutexName, out bool first);
            if (first)
            {
                var show = new EventWaitHandle(false, EventResetMode.AutoReset, eventName);
                var claimed = new SingleInstance(mutex, show, onShowRequested);
                mutex = null;
                return claimed;
            }
        }
        catch (UnauthorizedAccessException) { /* held by a PCPorter with other rights: it is running */ }
        finally { mutex?.Dispose(); }

        AskFirstToShow(eventName);
        return null;
    }

    static void AskFirstToShow(string eventName)
    {
        try
        {
            AllowSetForegroundWindow(ASFW_ANY);   // we were started by the person, so we may hand the foreground on
            if (EventWaitHandle.TryOpenExisting(eventName, out var show)) using (show) show.Set();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            Log.Information(ex, "Another PCPorter is running but could not be brought forward");
        }
    }

    public void Dispose()
    {
        _wait.Unregister(null);
        _show.Dispose();
        try { _mutex.ReleaseMutex(); } catch (ApplicationException) { /* released by another thread's exit */ }
        _mutex.Dispose();
    }

    const int ASFW_ANY = -1;

    [DllImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AllowSetForegroundWindow(int processId);
}
