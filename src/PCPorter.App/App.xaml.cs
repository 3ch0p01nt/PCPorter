using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;
using PCPorter.Core.Snapshots;
using Serilog;

namespace PCPorter.App;

/// <summary>
/// The entry point (StartupObject in the project file). It runs before the <see cref="App"/> object exists, because
/// creating it already loads WPF's native DLLs: a missing one would crash before <c>OnStartup</c> could say why.
/// </summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        App.HardenDllSearch();
        // Started from inside the zip, or a native DLL is gone (antivirus): say what to do in plain words.
        if (!StartupCheck.Passes(cli: args.Length > 0)) return ExitCodes.Failed;

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}

public partial class App : Application
{
    SingleInstance? _singleInstance;

    const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200, LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;

    /// <summary>Elevated app: never load DLLs from the current folder or PATH (DLL hijacking). First thing at start-up.</summary>
    internal static void HardenDllSearch()
    {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        SetDllDirectory("");
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        bool cli = e.Args.Length > 0;

        if (cli) ConsoleAttach.Apply();   // the caller's console, for each stream that is not redirected

        // Elevated, the log folder must be admin-only (AppFolders); when it cannot be made safe PCPorter stops here
        // with a clear message instead of crashing on its first log line.
        try { Logging.Init(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            var message = Logging.StartFailure(ex);
            if (cli) Console.Error.WriteLine(message);
            else MessageBox.Show(message, "PCPorter", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(ExitCodes.Failed);
            return;
        }

        // With arguments: run as a command-line tool and exit with a documented code.
        if (cli)
        {
            var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            var code = CliApp.Run(e.Args, elevated,
                ThumbsCommand.Create(elevated, (s, p) => PCPorter.Reports.GalleryJobFactory.Options(s, elevated, p)),
                HistoryCommand.Create(elevated),
                ScanCommand.Create(elevated),
                SelfTestCommand.Create(elevated));
            Log.Information("CLI command {Command} exited with {Code}", e.Args[0], code);   // arguments may hold secrets: never log them
            Shutdown(code);
            return;
        }

        _singleInstance = SingleInstance.TryClaim(() => Dispatcher.BeginInvoke(BringForward));
        if (_singleInstance is null)
        {
            Log.Information("PCPorter is already running: asked it to come forward");
            Shutdown(0);
            return;
        }

        CrashHandler.Install(this);
        base.OnStartup(e);
        Log.Information("PCPorter started");
        new MainWindow().Show();
        if (AppFolders.IsElevated) _ = Task.Run(CleanUpShadowCopies);
    }

    /// <summary>Another start asked: restore and activate the open window.</summary>
    void BringForward()
    {
        if (MainWindow is not { } w) return;
        if (w.WindowState == WindowState.Minimized) w.WindowState = WindowState.Normal;
        w.Show();
        w.Activate();
        w.Topmost = true;    // Activate alone may only flash the taskbar button
        w.Topmost = false;
        w.Focus();
    }

    /// <summary>Log-off or shut-down: no dialog is possible, so stop any job and give it a few seconds to clean up.</summary>
    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        if (RunningJobs.Instance.Any)
        {
            Log.Information("Windows is ending the session ({Reason}): stopping the running job", e.ReasonSessionEnding);
            if (!RunningJobs.Instance.StopAll(TimeSpan.FromSeconds(5))) Log.Warning("A job did not stop before the session ended");
        }
        base.OnSessionEnding(e);
    }

    /// <summary>Temporary shadow copies left by a PCPorter run that crashed or was killed (only ones PCPorter made).</summary>
    static void CleanUpShadowCopies()
    {
        try
        {
            var removed = new VssSnapshotProvider().CleanUpStale();
            if (removed > 0) Log.Information("Removed {Count} shadow copies left behind by an earlier PCPorter run", removed);
        }
        catch (Exception ex) { Log.Warning(ex, "Could not check for shadow copies left behind by an earlier run"); }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _singleInstance?.Dispose();
        Logging.Close();
        base.OnExit(e);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDefaultDllDirectories(uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string path);
}
