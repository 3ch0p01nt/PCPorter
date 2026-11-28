using System.IO;
using PCPorter.Core.Cli;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// Ctrl+C for a command: the first press asks the job to stop after its current step (it then cleans up and exits 6);
/// a second press ends the process at once with exit 6, for a step that does not come back.
/// </summary>
public sealed class CliCancel : IDisposable
{
    readonly CancellationTokenSource _cts = new();
    readonly Action<int> _exit;
    readonly TextWriter? _stderr;
    readonly bool _hooked;
    int _presses;

    /// <param name="exit">Ends the process (tests pass a fake).</param>
    /// <param name="hookConsole">False in tests: do not listen to the real Ctrl+C.</param>
    public CliCancel(Action<int>? exit = null, TextWriter? stderr = null, bool hookConsole = true)
    {
        _exit = exit ?? (code => { Log.Warning("Stopped at once by a second Ctrl+C"); Logging.Close(); Environment.Exit(code); });
        _stderr = stderr;
        _hooked = hookConsole;
        if (_hooked) Console.CancelKeyPress += OnCancelKeyPress;
    }

    public CancellationToken Token => _cts.Token;

    void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e) => e.Cancel = Press();

    /// <summary>One Ctrl+C. Returns true to keep the process running (the job stops by itself).</summary>
    public bool Press()
    {
        var err = _stderr ?? Console.Error;
        if (Interlocked.Increment(ref _presses) == 1)
        {
            err.WriteLine("Stopping after the current step... (press Ctrl+C again to quit at once)");
            _cts.Cancel();
            return true;
        }
        err.WriteLine("Stopped at once. A partly written case folder may remain.");
        _exit(ExitCodes.Cancelled);
        return true;
    }

    public void Dispose()
    {
        if (_hooked) Console.CancelKeyPress -= OnCancelKeyPress;
        _cts.Dispose();
    }
}
