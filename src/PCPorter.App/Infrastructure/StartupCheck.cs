using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// The published EXE keeps WPF's and SQLite's native DLLs beside it (no extraction to a temp folder that could be
/// swapped). Run from Explorer's zip view (Explorer copies the EXE alone to %TEMP%\Temp1_name.zip\) or after an
/// antivirus removed one of those DLLs, it would fail with a technical error. This check runs first, before WPF and
/// logging, and explains what to do in plain words.
/// </summary>
public static partial class StartupCheck
{
    /// <summary>The native files the single-file EXE needs next to it.</summary>
    public static readonly IReadOnlyList<string> NativeFiles =
    [
        "D3DCompiler_47_cor3.dll",
        "PenImc_cor3.dll",
        "PresentationNative_cor3.dll",
        "vcruntime140_cor3.dll",
        "wpfgfx_cor3.dll",
        "e_sqlite3.dll",
    ];

    /// <summary>The managed entry assembly. A dev build (dotnet build/run, tests) has it beside the EXE; the published
    /// single-file EXE holds it inside, so its absence is how a published run is recognized.</summary>
    public const string EntryAssemblyFile = "PCPorter.dll";

    /// <summary>
    /// Returns the message to show, or null when PCPorter can start. <paramref name="exeDir"/> is the folder of the
    /// running EXE, <paramref name="tempDir"/> the user's temp folder.
    /// </summary>
    public static string? Problem(string exeDir, string tempDir, Func<string, bool> fileExists)
    {
        // Dev builds and tests run from bin\ with every DLL loose; nothing to check.
        if (fileExists(Path.Combine(exeDir, EntryAssemblyFile))) return null;

        var missing = NativeFiles.FirstOrDefault(name => !fileExists(Path.Combine(exeDir, name)));
        if (missing is null && !IsInsideZipView(exeDir, tempDir)) return null;
        return Message(missing);
    }

    public static string Message(string? missingFile)
    {
        var text = "PCPorter can't start from here. Right-click the zip, choose Extract All, then run PCPorter.exe from the new folder.";
        if (missingFile is not null)
            text += $" If you already did, your antivirus may have removed one of its files: {missingFile}.";
        return text;
    }

    /// <summary>True for a folder Explorer made to run a file straight from a zip: %TEMP%\Temp1_name.zip\...</summary>
    public static bool IsInsideZipView(string exeDir, string tempDir)
    {
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(tempDir)) + Path.DirectorySeparatorChar;
        var dir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(exeDir)) + Path.DirectorySeparatorChar;
        if (!dir.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) return false;
        var first = dir[temp.Length..].Split(Path.DirectorySeparatorChar)[0];
        return ZipViewFolder().IsMatch(first);
    }

    [GeneratedRegex(@"^Temp\d*_.+\.zip$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ZipViewFolder();

    /// <summary>Runs the check for this process. Returns false (after telling the user) when PCPorter must stop.</summary>
    public static bool Passes(bool cli)
    {
        string? problem;
        try { problem = Problem(AppContext.BaseDirectory, Path.GetTempPath(), File.Exists); }
        catch (Exception) { return true; }   // a check that cannot run must never be the thing that stops PCPorter
        if (problem is null) return true;

        if (cli)
        {
            ConsoleAttach.Apply();   // PCPorter stops here, so this is the only attach of this run
            Console.Error.WriteLine(problem);
        }
        else MessageBoxW(IntPtr.Zero, problem, "PCPorter", MB_OK | MB_ICONERROR);
        return false;
    }

    const uint MB_OK = 0x0, MB_ICONERROR = 0x10;

    // user32 directly: when a WPF DLL is missing, WPF's own MessageBox may not load.
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
