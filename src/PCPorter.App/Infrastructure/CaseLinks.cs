using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// "Open the report" and "Open case folder" for an elevated app. The paths come from a finished job or from
/// settings.json (which the user, or malware running as the user, can edit), and an elevated ShellExecute would run
/// whatever handler the user registered with administrator rights. So only two kinds of path are ever opened:
/// a PCPorter case folder (<c>&lt;drive&gt;:\...\PCPorter\&lt;name&gt;_&lt;yyyyMMddTHHmmssZ&gt;_&lt;hex&gt;</c>) and an
/// <c>.html</c> file inside one; and they are handed to <c>%windir%\explorer.exe</c> by full path, which passes them
/// to the already running (not elevated) desktop shell.
/// </summary>
public static partial class CaseLinks
{
    /// <summary>The case folder name <see cref="PCPorter.Core.Case.CaseFolder"/> creates: computer, UTC time, 6 hex digits.</summary>
    [GeneratedRegex(@"^[\p{L}\p{Nd}_-]+_\d{8}T\d{6}Z_[0-9a-f]{6}$", RegexOptions.CultureInvariant)]
    private static partial Regex CaseName();

    /// <summary>A full local path (<c>X:\...</c>) already in normal form: no relative parts, no share, no device path.</summary>
    static bool IsPlainLocalPath(string path) =>
        path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        && path.IndexOfAny(Path.GetInvalidPathChars()) < 0 && path.IndexOf('/') < 0
        && string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal);

    /// <summary>True when <paramref name="path"/> is itself a PCPorter case folder (by name and place; existence not checked).</summary>
    public static bool LooksLikeCaseFolder(string? path)
    {
        if (string.IsNullOrEmpty(path) || !IsPlainLocalPath(path)) return false;
        var trimmed = Path.TrimEndingDirectorySeparator(path);
        var parent = Path.GetDirectoryName(trimmed);
        return parent is not null && CaseName().IsMatch(Path.GetFileName(trimmed))
               && string.Equals(Path.GetFileName(parent), "PCPorter", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when <paramref name="path"/> is an <c>.html</c> file somewhere inside a PCPorter case folder.</summary>
    public static bool LooksLikeReport(string? path)
    {
        if (string.IsNullOrEmpty(path) || !IsPlainLocalPath(path) || Path.EndsInDirectorySeparator(path)) return false;
        if (!string.Equals(Path.GetExtension(path), ".html", StringComparison.OrdinalIgnoreCase)) return false;
        for (var dir = Path.GetDirectoryName(path); dir is not null; dir = Path.GetDirectoryName(dir))
            if (LooksLikeCaseFolder(dir)) return true;
        return false;
    }

    /// <summary>A report that may be shown (and opened): the right shape and the file exists.</summary>
    public static bool IsReport(string? path, Func<string, bool>? fileExists = null) =>
        LooksLikeReport(path) && (fileExists ?? File.Exists)(path!);

    /// <summary>A case folder that may be shown (and opened): the right shape and the folder exists.</summary>
    public static bool IsCaseFolder(string? path, Func<string, bool>? dirExists = null) =>
        LooksLikeCaseFolder(path) && (dirExists ?? Directory.Exists)(path!);

    /// <summary>What is started for <paramref name="path"/>: the full path of Windows' own explorer.exe, never a lookup.</summary>
    public static ProcessStartInfo Explorer(string path)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
        { UseShellExecute = false };
        psi.ArgumentList.Add(path);
        return psi;
    }

    /// <summary>Opens a report in the person's browser (not elevated). Refuses anything that is not a case report.</summary>
    public static bool OpenReport(string? path) => IsReport(path) && Start(path!);

    /// <summary>Opens a case folder in File Explorer (not elevated). Refuses anything that is not a case folder.</summary>
    public static bool OpenCaseFolder(string? path) => IsCaseFolder(path) && Start(path!);

    /// <summary>PCPorter's own log folder (a fixed, known path) in File Explorer.</summary>
    public static bool OpenFolder(string folder) => Start(folder);

    static bool Start(string path)
    {
        try { using var _ = Process.Start(Explorer(path)); return true; }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Log.Warning(ex, "could not open a folder or report in File Explorer");
            return false;
        }
    }
}
