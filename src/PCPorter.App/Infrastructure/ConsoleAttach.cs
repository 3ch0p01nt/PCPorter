using System.Runtime.InteropServices;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// PCPorter is a Windows (GUI) program, so a command run from a console has no console of its own. It attaches to the
/// caller's console for every stream that is NOT redirected: attaching replaces a stdout that points at a file
/// ("pcporter scan --json &gt; out.json" used to produce an empty file), and with stdout redirected the progress
/// and error lines on stderr used to go nowhere.
/// </summary>
/// <remarks>
/// Windows does not wait for a GUI program and <c>start /wait</c> in cmd reports 0 whatever it returns. To read the real
/// exit code use PowerShell: <c>&amp; pcporter scan --out E:\ --json | Out-String; $LASTEXITCODE</c>.
/// </remarks>
public static class ConsoleAttach
{
    public enum Plan
    {
        /// <summary>Both streams go to files or pipes: nothing to attach.</summary>
        None,
        /// <summary>Neither is redirected: attach, and both streams use the console.</summary>
        Attach,
        /// <summary>Only stdout is redirected: attach for stderr, and keep the redirected stdout.</summary>
        AttachForStderr,
    }

    public static Plan Decide(bool stdoutRedirected, bool stderrRedirected) => (stdoutRedirected, stderrRedirected) switch
    {
        (false, _) => Plan.Attach,
        (true, false) => Plan.AttachForStderr,
        (true, true) => Plan.None,
    };

    /// <summary>Call once at start-up, before anything touches <see cref="Console"/>.</summary>
    public static void Apply()
    {
        var stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        var stderr = GetStdHandle(STD_ERROR_HANDLE);
        bool outRedirected = IsRedirected(stdout), errRedirected = IsRedirected(stderr);
        var plan = Decide(outRedirected, errRedirected);
        if (plan == Plan.None || !AttachConsole(ATTACH_PARENT_PROCESS)) return;

        // Attaching may point the standard handles at the console: a stream sent to a file or pipe keeps going there.
        if (outRedirected) SetStdHandle(STD_OUTPUT_HANDLE, stdout);
        if (errRedirected) SetStdHandle(STD_ERROR_HANDLE, stderr);
        if (plan == Plan.AttachForStderr)
        {
            var console = CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (console != INVALID_HANDLE_VALUE) SetStdHandle(STD_ERROR_HANDLE, console);
        }
    }

    static bool IsRedirected(IntPtr handle) => GetFileType(handle) is FILE_TYPE_DISK or FILE_TYPE_PIPE;

    const int ATTACH_PARENT_PROCESS = -1;
    const int STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12;
    const uint FILE_TYPE_DISK = 1, FILE_TYPE_PIPE = 3;
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;
    static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AttachConsole(int processId);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr GetStdHandle(int stdHandle);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetStdHandle(int stdHandle, IntPtr handle);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetFileType(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
}
