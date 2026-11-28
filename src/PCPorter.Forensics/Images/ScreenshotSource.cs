namespace PCPorter.Forensics.Images;

/// <summary>
/// Screenshots the user took: the Screenshots folder (local and OneDrive) and the Snipping Tool's
/// temporary snips. These prove the picture was on screen. Read-only; never throws from Collect.
/// </summary>
public sealed class ScreenshotSource : IImageEvidenceSource
{
    private const string TimeMeaning = "screenshot file created / last changed";
    private static readonly string[] ScreenshotExtensions = [".png", ".jpg", ".jpeg", ".gif", ".bmp"];

    public string Name => "Screenshots";

    public IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        var places = new (string Label, string Folder, bool Recurse)[]
        {
            ("Screenshots folder", Path.Combine(context.ProfileFolder, "Pictures", "Screenshots"), false),
            ("OneDrive Screenshots folder", Path.Combine(context.ProfileFolder, "OneDrive", "Pictures", "Screenshots"), false),
            ("Snipping Tool", Path.Combine(context.ProfileFolder, "AppData", "Local", "Packages",
                "Microsoft.ScreenSketch_8wekyb3d8bbwe", "TempState"), true),
        };

        foreach (var (label, folder, recurse) in places)
        {
            int cloudOnly = 0;
            foreach (var file in SafeEnumerate(folder, recurse, context.Warnings, label))
            {
                if (cancellationToken.IsCancellationRequested) yield break;
                if (IsCandidate(file) && ImageFiles.IsCloudOnly(file)) { cloudOnly++; continue; }   // never download it
                var evidence = TryRead(context, label, file);
                if (evidence is not null) yield return evidence;
            }
            ImageFiles.AddCloudNote(context, label, cloudOnly);
        }
    }

    private static bool IsCandidate(string file)
    {
        var ext = Path.GetExtension(file);
        return ext.Length == 0 || ScreenshotExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
    }

    private static List<string> SafeEnumerate(string folder, bool recurse, IList<string> warnings, string label)
    {
        try
        {
            if (!Directory.Exists(folder)) return [];
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = recurse,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };
            return Directory.EnumerateFiles(folder, "*", options).ToList();
        }
        catch (Exception ex)
        {
            warnings.Add($"{label}: could not list files ({ex.GetType().Name}).");
            return [];
        }
    }

    private static ImageEvidence? TryRead(ImageSourceContext context, string label, string file)
    {
        try
        {
            if (!IsCandidate(file)) return null;                    // only extension-less files are sniffed
            bool knownExtension = Path.GetExtension(file).Length > 0;

            var info = new FileInfo(file);
            if (info.Length == 0) return null;

            string? contentType = ImageFiles.SniffContentType(ImageFiles.ReadHead(file, 16));
            if (contentType is null && !knownExtension) return null; // extension-less and not a picture
            contentType ??= ImageFiles.ContentTypeFromExtension(file);

            if (info.Length > ImageFiles.MaxImageBytes)
            {
                context.Warnings.Add($"{label}: skipped {info.Name} because it is larger than 30 MB.");
                return null;
            }

            return new ImageEvidence(
                Source: label,
                Evidence: EvidenceLevel.OnScreen,
                User: context.User,
                OriginalPath: file,
                Url: null,
                FirstSeenUtc: ImageFiles.Plausible(info.CreationTimeUtc),
                LastSeenUtc: ImageFiles.Plausible(info.LastWriteTimeUtc),
                TimeMeaning: TimeMeaning,
                ImageBytes: ImageFiles.ReadAll(file),
                ContentType: contentType);
        }
        catch (Exception ex)
        {
            context.Warnings.Add($"{label}: could not read {Path.GetFileName(file)} ({ex.GetType().Name}).");
            return null;
        }
    }
}
