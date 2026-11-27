using System.Windows.Controls;
using PCPorter.Core.Config;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// The pages' memory across app starts (%AppData%\PCPorter\settings.json). A settings problem is logged and ignored:
/// the page then simply starts with its defaults.
/// </summary>
static class Remembered
{
    public static readonly PageMemoryStore Pages = new(new SettingsStore(SettingsStore.DefaultDirectory),
        ex => Log.Warning(ex, "settings could not be read or saved; carrying on without them"));

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
