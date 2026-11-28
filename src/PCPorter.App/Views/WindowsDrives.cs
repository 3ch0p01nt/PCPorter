using System.IO;

namespace PCPorter.App.Views;

/// <summary>A drive in the "another PC's drive" picker. Locked (BitLocker) drives are listed but can't be picked until unlocked.</summary>
public sealed record DriveChoice(string Root, string Label, bool Usable)
{
    public override string ToString() => Label;
}

/// <summary>Finds connected drives that hold another PC's Windows (shared by the Health and security and Web history pages).</summary>
public static class WindowsDrives
{
    /// <summary>Every fixed or removable drive other than the running Windows that has a SOFTWARE hive. Slow for a sleeping USB disk: call off the UI thread.</summary>
    public static List<DriveChoice> Find()
    {
        var running = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        var list = new List<DriveChoice>();
        foreach (var d in DriveInfo.GetDrives())
        {
            var root = d.RootDirectory.FullName;
            if (string.Equals(root, running, StringComparison.OrdinalIgnoreCase) || d.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
            try
            {
                if (!d.IsReady) { list.Add(new(root, $"{root} (locked or not ready)", false)); continue; }
                if (File.Exists(Path.Combine(root, "Windows", "System32", "config", "SOFTWARE")))
                    list.Add(new(root, string.IsNullOrWhiteSpace(d.VolumeLabel) ? root : $"{root} ({d.VolumeLabel})", true));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { list.Add(new(root, $"{root} (can't be read)", false)); }
        }
        return list;
    }

    /// <summary>
    /// The line under the picker: what was found and what to do next. Without administrator rights Windows hides another
    /// drive's system folder, so "nothing found" would be wrong: say how to look instead.
    /// </summary>
    public static string Hint(IReadOnlyCollection<DriveChoice> found, bool elevated) =>
        found.Count == 0
            ? elevated
                ? "No other Windows drive found. Connect the old PC's drive (for example with a USB adapter) and press Refresh."
                : "Start PCPorter as administrator to look inside other drives."
            : found.Any(c => !c.Usable)
                ? "A locked drive was found. Unlock it in File Explorer with its BitLocker recovery key (aka.ms/myrecoverykey), then press Refresh."
                : "";

    /// <summary>A local folder outside any synced location: shown at once, until the backup drive is found.</summary>
    public const string DefaultSaveFolder = @"C:\PCPorterCases";

    /// <summary>
    /// The first connected removable drive (the backup drive), else <see cref="DefaultSaveFolder"/>. Slow for a sleeping
    /// USB disk (IsReady waits for it): call off the UI thread.
    /// </summary>
    public static string SuggestedSaveFolder()
    {
        try { return DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.DriveType == DriveType.Removable)?.RootDirectory.FullName ?? DefaultSaveFolder; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return DefaultSaveFolder; }
    }

    /// <summary>
    /// Fills a page's save-folder box without blocking the window: <see cref="DefaultSaveFolder"/> at once, then the
    /// backup drive when found, unless the person has changed the box in the meantime.
    /// </summary>
    public static async Task SuggestSaveFolderAsync(Func<string> get, Action<string> set, Func<string>? find = null)
    {
        set(DefaultSaveFolder);
        var found = await Task.Run(find ?? SuggestedSaveFolder);
        if (get() == DefaultSaveFolder) set(found);
    }
}
