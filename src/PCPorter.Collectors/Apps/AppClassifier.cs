using System.Text.RegularExpressions;

namespace PCPorter.Collectors.Apps;

/// <summary>Runtime / Driver / Game / Win32 classification of registry apps (Task 5a rule 5).</summary>
public static class AppClassifier
{
    const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>Shared runtimes and Windows components: never offered for reinstall.</summary>
    public static readonly IReadOnlyDictionary<string, Regex> RuntimePatterns = new Dictionary<string, Regex>
    {
        ["VcRedist"] = new(@"^Microsoft Visual C\+\+ .*(Redistributable|Runtime)", O),
        ["DotNet"] = new(@"\.NET (Runtime|Desktop Runtime|Windows Desktop Runtime)", O),
        ["AspNetCore"] = new(@"ASP\.NET Core", O),
        ["WindowsDesktopRuntime"] = new(@"Windows Desktop Runtime", O),
        ["DirectX"] = new(@"DirectX", O),
        ["WebView2"] = new(@"Edge WebView2", O),
        ["Edge"] = new(@"^Microsoft Edge( Update)?$", O),
        ["UpdateHealthTools"] = new(@"Update Health Tools", O),
        ["GameInput"] = new(@"GameInput", O),
    };

    public static readonly Regex DriverPattern = new(@"^(NVIDIA|AMD|Realtek|Intel\(R\)).*(Driver|Graphics|Audio|Chipset|Management Engine)", O);
    public static readonly Regex SteamAppPattern = new(@"^Steam App \d+$", O);

    /// <param name="gameLibraries">Folders (as the scanned PC knows them) that hold Steam/Epic games.</param>
    public static AppKind Classify(string name, string? installLocation, IEnumerable<string> gameLibraries)
    {
        foreach (var r in RuntimePatterns.Values) if (r.IsMatch(name)) return AppKind.Runtime;
        if (DriverPattern.IsMatch(name)) return AppKind.Driver;
        if (SteamAppPattern.IsMatch(name)) return AppKind.Game;
        if (installLocation is { Length: > 3 } && gameLibraries.Any(lib => PathUtil.IsUnder(installLocation, lib))) return AppKind.Game;
        return AppKind.Win32;
    }
}

static class PathUtil
{
    /// <summary>Case-insensitive "path is the folder or inside it" with a folder boundary.</summary>
    public static bool IsUnder(string path, string folder)
    {
        var p = Clean(path);
        var f = Clean(folder);
        if (f.Length < 3) return false;
        return p.Equals(f, StringComparison.OrdinalIgnoreCase) || p.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase);
    }

    public static string Clean(string path) => path.Trim().Trim('"').Replace('/', '\\').TrimEnd('\\');

    /// <summary>The executable path at the start of a command line ("C:\x\a.exe" /S -> C:\x\a.exe); null if not absolute.</summary>
    public static string? ExeOf(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var c = commandLine.Trim();
        string exe;
        if (c.StartsWith('"')) { var end = c.IndexOf('"', 1); exe = end > 0 ? c[1..end] : c.Trim('"'); }
        else
        {
            var i = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            exe = i > 0 ? c[..(i + 4)] : c.Split(' ')[0];
        }
        exe = exe.Split(',')[0].Trim();
        return exe.Length > 3 && exe[1] == ':' && exe[2] == '\\' ? exe : null;
    }
}
