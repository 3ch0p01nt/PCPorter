namespace PCPorter.Forensics.Images;

/// <summary>
/// Detect-only checks for picture data that exists but is not used as evidence. Only tests whether
/// folders/files exist; never opens them.
/// </summary>
public static class WindowsRecallDetector
{
    public const string RecallNote = "Windows Recall data exists on this PC but is encrypted by Windows and can't be read.";

    public const string PhotosIndexNote =
        "The Photos app keeps a picture index (MediaDb) on this PC. It lists pictures the app found, not pictures anyone viewed.";

    /// <summary>Plain-English notes for the report, or null when there is nothing to mention.</summary>
    public static string? Detect(string profileFolder)
    {
        var notes = DetectAll(profileFolder);
        return notes.Count == 0 ? null : string.Join(" ", notes);
    }

    /// <summary>Each note separately (Recall first, then the Photos index).</summary>
    public static IReadOnlyList<string> DetectAll(string profileFolder)
    {
        var notes = new List<string>();
        if (string.IsNullOrWhiteSpace(profileFolder)) return notes;
        try
        {
            var local = Path.Combine(profileFolder, "AppData", "Local");
            if (Directory.Exists(Path.Combine(local, "CoreAIPlatform.00", "UKP")))
                notes.Add(RecallNote);

            var photos = Path.Combine(local, "Packages", "Microsoft.Windows.Photos_8wekyb3d8bbwe", "LocalState");
            if (File.Exists(Path.Combine(photos, "MediaDb.v1.sqlite")))
                notes.Add(PhotosIndexNote);
        }
        catch (Exception)
        {
            // Existence checks only; an unusable path simply means nothing to report.
        }
        return notes;
    }
}
