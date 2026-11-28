using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;
using PCPorter.Core.Snapshots;
using Serilog;

namespace PCPorter.App;

public partial class App : Application
{
    Mutex? _singleInstance;

    const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200, LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Elevated app: never load DLLs from the current folder or PATH (DLL hijacking).
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        SetDllDirectory("");
        Logging.Init();

        // With arguments: run as a command-line tool and exit with a documented code.
        if (e.Args.Length > 0)
        {
            // Attach to the caller's console only when output is NOT already redirected: attaching replaces a stdout
            // that points at a file, so "pcporter scan --json > out.json" used to produce an empty file.
            if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) is not (FILE_TYPE_DISK or FILE_TYPE_PIPE)) AttachConsole(-1);
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

        _singleInstance = new Mutex(true, @"Global\PCPorter-7d1f6a2e", out bool isFirst);
        if (!isFirst)
        {
            MessageBox.Show("PCPorter is already running.", "PCPorter", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
            return;
        }

        CrashHandler.Install(this);
        base.OnStartup(e);
        Log.Information("PCPorter started");
        new MainWindow().Show();
        if (AppFolders.IsElevated) _ = Task.Run(CleanUpShadowCopies);
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

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AttachConsole(int processId);

    const int STD_OUTPUT_HANDLE = -11;
    const uint FILE_TYPE_DISK = 1, FILE_TYPE_PIPE = 3;

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr GetStdHandle(int stdHandle);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetFileType(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDefaultDllDirectories(uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string path);
}
