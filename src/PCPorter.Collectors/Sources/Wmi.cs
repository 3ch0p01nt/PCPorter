using System.Diagnostics;
using System.Management;

namespace PCPorter.Collectors.Sources;

public enum WmiOutcome { Ok, InvalidNamespace, AccessDenied, TimedOut, Error }

public sealed record WmiResult(WmiOutcome Outcome, IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string? Message = null)
{
    public static WmiResult Fail(WmiOutcome o, string? m = null) => new(o, [], m);
}

/// <summary>WMI queries behind an interface so collectors are testable without a real PC.</summary>
public interface IWmiClient
{
    WmiResult Query(string ns, string wql, TimeSpan? timeout = null);
}

/// <summary>
/// Runs each WMI query on its own background thread with a timeout (WMI can hang forever on a struggling disk).
/// A hung query keeps only its own thread, never a thread-pool worker; after <see cref="MaxStuck"/> hung queries
/// the client stops asking and answers TimedOut at once, so a broken WMI cannot stall the whole scan.
/// </summary>
public sealed class WmiClient : IWmiClient
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);
    public const int MaxStuck = 4;
    int _stuck;

    public WmiResult Query(string ns, string wql, TimeSpan? timeout = null)
    {
        var limit = timeout ?? DefaultTimeout;
        if (Volatile.Read(ref _stuck) >= MaxStuck)
            return WmiResult.Fail(WmiOutcome.TimedOut, "WMI stopped answering earlier in this scan; skipped.");
        var done = new TaskCompletionSource<WmiResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var r = Run(ns, wql, limit);
            if (!done.TrySetResult(r)) Interlocked.Decrement(ref _stuck);   // answered late: the thread is free again
        }) { IsBackground = true, Name = "PCPorter WMI" };
        thread.Start();
        if (done.Task.Wait(limit + TimeSpan.FromSeconds(2))) return done.Task.Result;
        var timedOut = WmiResult.Fail(WmiOutcome.TimedOut, $"No answer within {limit.TotalSeconds:0} s.");
        if (!done.TrySetResult(timedOut)) return done.Task.Result;            // it answered at the last moment
        Interlocked.Increment(ref _stuck);
        return timedOut;
    }

    static WmiResult Run(string ns, string wql, TimeSpan limit)
    {
            try
            {
                var scope = new ManagementScope(ns);
                scope.Connect();
                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql),
                    new System.Management.EnumerationOptions { Timeout = limit, ReturnImmediately = true, Rewindable = false });
                var rows = new List<IReadOnlyDictionary<string, object?>>();
                foreach (ManagementBaseObject o in searcher.Get())
                    using (o)
                    {
                        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                        foreach (var p in o.Properties) row[p.Name] = p.Value;
                        rows.Add(row);
                    }
                return new WmiResult(WmiOutcome.Ok, rows);
            }
            catch (ManagementException e) when (e.ErrorCode == ManagementStatus.InvalidNamespace) { return WmiResult.Fail(WmiOutcome.InvalidNamespace, e.Message); }
            catch (ManagementException e) when (e.ErrorCode is ManagementStatus.AccessDenied) { return WmiResult.Fail(WmiOutcome.AccessDenied, e.Message); }
            catch (UnauthorizedAccessException e) { return WmiResult.Fail(WmiOutcome.AccessDenied, e.Message); }
            catch (ManagementException e) when (e.ErrorCode == ManagementStatus.Timedout) { return WmiResult.Fail(WmiOutcome.TimedOut, e.Message); }
            catch (Exception e) when (e is ManagementException or System.Runtime.InteropServices.COMException) { return WmiResult.Fail(WmiOutcome.Error, e.Message); }
            catch (Exception e) { return WmiResult.Fail(WmiOutcome.Error, e.GetType().Name + ": " + e.Message); }   // never crash the thread
    }
}

public sealed record ProcessResult(int ExitCode, string StdOut, bool TimedOut);

/// <summary>Starts helper programs. Only absolute paths under %SystemRoot%\System32 are allowed (never PATH or user folders).</summary>
public interface IProcessRunner
{
    ProcessResult Run(string system32Exe, IReadOnlyList<string> args, TimeSpan timeout);
}

public sealed class ProcessRunner : IProcessRunner
{
    public ProcessResult Run(string system32Exe, IReadOnlyList<string> args, TimeSpan timeout)
    {
        var system32 = Environment.SystemDirectory;
        var exe = Path.IsPathRooted(system32Exe) ? system32Exe : Path.Combine(system32, system32Exe);
        if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(exe)), system32, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException($"PCPorter only starts programs from {system32}.");
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = system32 };
        foreach (var a in args) psi.ArgumentList.Add(a);
        CleanEnvironment(psi.Environment, system32);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        _ = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeout)) { try { p.Kill(true); } catch (InvalidOperationException) { } return new ProcessResult(-1, "", true); }
        // A grandchild can keep the pipe open after the helper exits: never wait forever for the rest of the output.
        if (!stdout.Wait(TimeSpan.FromSeconds(5))) return new ProcessResult(p.ExitCode, "", true);
        return new ProcessResult(p.ExitCode, stdout.Result, false);
    }

    /// <summary>
    /// Helpers run elevated: drop variables that make Windows tools or runtimes load code from elsewhere
    /// (PATH search, PowerShell modules, .NET profilers/startup hooks) and pin PATH to Windows' own folders.
    /// </summary>
    internal static void CleanEnvironment(IDictionary<string, string?> env, string system32)
    {
        foreach (var key in env.Keys.ToList())
            if (key.StartsWith("COMPLUS_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("COR_", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("CORECLR_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("PSModulePath", StringComparison.OrdinalIgnoreCase) || key.Equals("__PSLockdownPolicy", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("PATHEXT", StringComparison.OrdinalIgnoreCase))
                env.Remove(key);
        var windows = Path.GetDirectoryName(system32)!;
        env["PATH"] = string.Join(';', system32, windows, Path.Combine(system32, "Wbem"), Path.Combine(system32, "WindowsPowerShell", "v1.0"));
        env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD";
    }
}
