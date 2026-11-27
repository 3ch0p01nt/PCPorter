using System.Windows.Controls;
using PCPorter.Core.Config;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// The pages' memory across app starts (%AppData%\PCPorter\settings.json). A settings problem is logged and ignored:
/// the page then simply starts with its defaults.
/// </summary>
public static class Remembered
{
    public static readonly PageMemoryStore Pages = new(new SettingsStore(SettingsStore.DefaultDirectory),
        ex => Log.Warning(ex, "settings could not be read or saved; carrying on without them"));

    /// <summary>
    /// The page's last finished run, only while its report still exists AND is a PCPorter case report: settings.json is
    /// writable by the user, and the elevated app must not offer to open whatever path was written there.
    /// </summary>
    public static LastRun? LastRunOf(string page) => Recall(Pages.RecallLastRun(page));

    /// <summary>Drops a remembered run whose report is not a case report, and a case folder that is not a case folder.</summary>
    public static LastRun? Recall(LastRun? run, Func<string, bool>? fileExists = null, Func<string, bool>? dirExists = null)
    {
        if (run is null || !CaseLinks.IsReport(run.ReportPath, fileExists)) return null;
        return CaseLinks.IsCaseFolder(run.CaseFolder, dirExists) ? run : run with { CaseFolder = null };
    }

    /// <summary>Ticks each box as remembered; boxes never remembered keep their XAML default.</summary>
    public static void RestoreOptions(PageMemory m, params (string Name, CheckBox Box)[] boxes)
    {
        foreach (var (name, box) in boxes)
            if (m.Options?.TryGetValue(name, out var on) == true) box.IsChecked = on;
    }

    /// <summary>
    /// The options to remember: only boxes the user can change right now. A box forced on or off (greyed because PCPorter
    /// is not administrator, or for another PC's drive) keeps the choice remembered before.
    /// </summary>
    public static Dictionary<string, bool> Options(PageMemory m, params (string Name, CheckBox Box, bool UserChoice)[] boxes)
    {
        var options = new Dictionary<string, bool>(m.Options ?? []);
        foreach (var (name, box, userChoice) in boxes)
            if (userChoice) options[name] = box.IsChecked == true;
        return options;
    }
}
