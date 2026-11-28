using System.Globalization;
using System.Text;
using Lnk;

namespace PCPorter.Forensics.Images;

/// <summary>
/// Pictures and videos the user opened, from the Recent files shortcuts (*.lnk) and the Jump Lists
/// (*.automaticDestinations-ms). Files are parsed offline with Eric Zimmerman's Lnk/JumpList libraries;
/// nothing is resolved through the live shell. Read-only; never throws from Collect.
/// </summary>
public sealed class RecentImageOpensSource : IImageEvidenceSource
{
    internal const string ShortcutSource = "Recent files (shortcuts)";
    internal const string ShortcutTimeMeaning = "shortcut created (first opened) / shortcut last changed (last opened)";
    internal const string JumpListTimeMeaning = "last opened (Jump List)";
    internal const string MissingNote = "file no longer exists";
    internal const string CloudOnlyNote = "file is stored only online (not downloaded)";

    static RecentImageOpensSource()
    {
        // The Lnk/JumpList libraries decode ANSI strings with code page 1252.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public string Name => "Recent files and Jump Lists";

    public IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        var recent = Path.Combine(context.ProfileFolder, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
        var cloudPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // the same online file can be in several lists

        foreach (var lnkPath in SafeEnumerate(recent, "*.lnk", context.Warnings, "Recent files"))
        {
            if (cancellationToken.IsCancellationRequested) yield break;
            var evidence = TryShortcut(context, lnkPath);
            if (evidence is null) continue;
            if (IsCloudOnly(evidence)) cloudPaths.Add(evidence.OriginalPath!);
            yield return evidence;
        }

        var auto = Path.Combine(recent, "AutomaticDestinations");
        foreach (var jumpPath in SafeEnumerate(auto, "*.automaticDestinations-ms", context.Warnings, "Jump Lists"))
        {
            if (cancellationToken.IsCancellationRequested) yield break;
            foreach (var evidence in TryJumpList(context, jumpPath, cancellationToken))
            {
                if (IsCloudOnly(evidence)) cloudPaths.Add(evidence.OriginalPath!);
                yield return evidence;
            }
        }
        ImageFiles.AddCloudNote(context, "Recently opened files", cloudPaths.Count);
    }

    private static bool IsCloudOnly(ImageEvidence e) =>
        e.OriginalPath is not null && e.Note is { } n && n.Contains(CloudOnlyNote, StringComparison.Ordinal);

    // ---- Recent .lnk ----

    private static ImageEvidence? TryShortcut(ImageSourceContext context, string lnkPath)
    {
        try
        {
            var lnk = Lnk.Lnk.LoadFile(lnkPath);
            var info = new FileInfo(lnkPath);
            return MapShortcut(context, lnk, info.CreationTimeUtc, info.LastWriteTimeUtc, Path.GetFileNameWithoutExtension(lnkPath));
        }
        catch (Exception ex)
        {
            context.Warnings.Add($"Recent files: could not read shortcut {Path.GetFileName(lnkPath)} ({ex.GetType().Name}).");
            return null;
        }
    }

    internal static ImageEvidence? MapShortcut(
        ImageSourceContext context, LnkFile lnk, DateTime lnkCreatedUtc, DateTime lnkModifiedUtc, string fallbackName)
    {
        var target = TargetPath(lnk);
        var nameOnly = target is null;
        target ??= fallbackName;
        if (!IsWanted(target)) return null;

        var notes = new List<string>();
        if (nameOnly) notes.Add("the shortcut records only the file name, not its folder");
        var recorded = RecordedTargetTimes(lnk.Header);
        if (recorded is not null) notes.Add(recorded);
        var (bytes, contentType, availability) = nameOnly ? (null, ImageFiles.ContentTypeFromExtension(target), null) : LoadTarget(target, context.ProfileFolder);
        if (availability is not null) notes.Insert(0, availability);

        return new ImageEvidence(
            Source: ShortcutSource,
            Evidence: EvidenceLevel.Opened,
            User: context.User,
            OriginalPath: target,
            Url: null,
            FirstSeenUtc: ImageFiles.Plausible(lnkCreatedUtc),
            LastSeenUtc: ImageFiles.Plausible(lnkModifiedUtc),
            TimeMeaning: ShortcutTimeMeaning,
            ImageBytes: bytes,
            ContentType: contentType,
            Note: notes.Count == 0 ? null : string.Join("; ", notes),
            VolumeSerial: nameOnly ? null : VolumeSerial(lnk));
    }

    /// <summary>The serial of the volume the target was on when the shortcut was written (LinkInfo VolumeID), if recorded.</summary>
    internal static uint? VolumeSerial(LnkFile? lnk)
    {
        var text = lnk?.VolumeInfo?.VolumeSerialNumber?.Trim();
        if (string.IsNullOrEmpty(text)) return null;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        text = text.Replace("-", "", StringComparison.Ordinal);
        return uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) && v != 0 ? v : null;
    }

    /// <summary>Target path from the shortcut's LinkInfo (local or network), else relative path + working directory.</summary>
    internal static string? TargetPath(LnkFile? lnk)
    {
        if (lnk is null) return null;
        if (!string.IsNullOrWhiteSpace(lnk.LocalPath))
            return JoinSuffix(lnk.LocalPath, lnk.CommonPath);
        var share = lnk.NetworkShareInfo?.NetworkShareName;
        if (!string.IsNullOrWhiteSpace(share))
            return JoinSuffix(share, lnk.CommonPath);
        if (!string.IsNullOrWhiteSpace(lnk.RelativePath) && !string.IsNullOrWhiteSpace(lnk.WorkingDirectory))
        {
            try { return Path.GetFullPath(Path.Combine(lnk.WorkingDirectory, lnk.RelativePath)); }
            catch (Exception) { return null; }
        }
        return null;
    }

    private static string JoinSuffix(string basePath, string? suffix)
    {
        if (string.IsNullOrEmpty(suffix)) return basePath;
        return basePath.EndsWith('\\') ? basePath + suffix : basePath + "\\" + suffix;
    }

    private static string? RecordedTargetTimes(Lnk.Header? header)
    {
        if (header is null) return null;
        var parts = new List<string>();
        if (header.TargetCreationDateRaw != 0 && ImageFiles.Plausible(header.TargetCreationDate) is { } c)
            parts.Add("created " + Format(c));
        if (header.TargetModificationDateRaw != 0 && ImageFiles.Plausible(header.TargetModificationDate) is { } m)
            parts.Add("modified " + Format(m));
        if (header.TargetLastAccessedDateRaw != 0 && ImageFiles.Plausible(header.TargetLastAccessedDate) is { } a)
            parts.Add("accessed " + Format(a));
        return parts.Count == 0 ? null : "file times saved in the shortcut: " + string.Join(", ", parts) + " (UTC)";
    }

    private static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    // ---- Jump Lists ----

    /// <summary>The parts of a Jump List entry this source uses (seam for tests).</summary>
    internal sealed record JumpListItem(string? TargetPath, DateTimeOffset? LastOpened, int InteractionCount, bool Pinned, uint? VolumeSerial = null);

    private static IEnumerable<ImageEvidence> TryJumpList(ImageSourceContext context, string jumpPath, CancellationToken cancellationToken)
    {
        List<JumpListItem> items;
        string app;
        try
        {
            var jump = JumpList.JumpList.LoadAutoJumplist(jumpPath);
            app = string.IsNullOrWhiteSpace(jump.AppId?.Description) ? "unknown app" : jump.AppId.Description;
            items = [];
            foreach (var entry in jump.DestListEntries ?? [])
            {
                string? target = TargetPath(entry.Lnk);
                if (target is null && !string.IsNullOrWhiteSpace(entry.Path)) target = entry.Path;
                items.Add(new JumpListItem(target, entry.LastModified, entry.InteractionCount, entry.Pinned, VolumeSerial(entry.Lnk)));
            }
        }
        catch (Exception ex)
        {
            context.Warnings.Add($"Jump Lists: could not read {Path.GetFileName(jumpPath)} ({ex.GetType().Name}).");
            yield break;
        }

        foreach (var item in items)
        {
            if (cancellationToken.IsCancellationRequested) yield break;
            ImageEvidence? evidence;
            try { evidence = MapJumpListItem(context, app, item); }
            catch (Exception ex)
            {
                context.Warnings.Add($"Jump Lists: skipped an entry in {Path.GetFileName(jumpPath)} ({ex.GetType().Name}).");
                continue;
            }
            if (evidence is not null) yield return evidence;
        }
    }

    internal static ImageEvidence? MapJumpListItem(ImageSourceContext context, string appName, JumpListItem item)
    {
        if (!IsWanted(item.TargetPath)) return null;
        var target = item.TargetPath!;

        var notes = new List<string>();
        var (bytes, contentType, availability) = LoadTarget(target, context.ProfileFolder);
        if (availability is not null) notes.Add(availability);
        if (item.InteractionCount > 0)
            notes.Add(item.InteractionCount == 1 ? "opened 1 time" : $"opened {item.InteractionCount} times");
        if (item.Pinned) notes.Add("pinned in the Jump List");

        return new ImageEvidence(
            Source: $"Jump List ({appName})",
            Evidence: EvidenceLevel.Opened,
            User: context.User,
            OriginalPath: target,
            Url: null,
            FirstSeenUtc: null,
            LastSeenUtc: ImageFiles.Plausible(item.LastOpened),
            TimeMeaning: JumpListTimeMeaning,
            ImageBytes: bytes,
            ContentType: contentType,
            Note: notes.Count == 0 ? null : string.Join("; ", notes),
            VolumeSerial: item.VolumeSerial);
    }

    // ---- shared ----

    internal static bool IsWanted(string? path) => ImageFiles.IsImageExtension(path) || ImageFiles.IsVideoExtension(path);

    /// <summary>
    /// Loads the target picture when it still exists on the scanned drive and is small enough.
    /// Returns a note when it is missing or could not be checked. Network paths are never touched.
    /// </summary>
    private static (byte[]? Bytes, string? ContentType, string? Note) LoadTarget(string target, string profileFolder)
    {
        var contentType = ImageFiles.ContentTypeFromExtension(target);
        var local = MapToSource(target, profileFolder);
        if (local is null) return (null, contentType, "file is on another drive or a network location (not checked)");

        try
        {
            var info = new FileInfo(local);
            if (!info.Exists) return (null, contentType, MissingNote);
            if (ImageFiles.IsCloudOnly(local)) return (null, contentType, CloudOnlyNote);
            if (!ImageFiles.IsImageExtension(target)) return (null, contentType, "file still exists (video, not loaded)");
            if (info.Length > ImageFiles.MaxImageBytes) return (null, contentType, "file still exists but is larger than 30 MB (not loaded)");
            var bytes = ImageFiles.ReadAll(local);
            return (bytes, ImageFiles.SniffContentType(bytes) ?? contentType, null);
        }
        catch (Exception ex)
        {
            return (null, contentType, $"file could not be read ({ex.GetType().Name})");
        }
    }

    /// <summary>
    /// Maps a target path recorded on the scanned PC to a path we can check: same drive as the profile
    /// as-is, or a path inside the user's profile re-rooted onto the profile's drive (offline drives).
    /// Null for network paths, other drives, or anything unparseable.
    /// </summary>
    internal static string? MapToSource(string target, string profileFolder)
    {
        try
        {
            if (target.StartsWith(@"\\", StringComparison.Ordinal)) return null;
            if (target.Length < 3 || target[1] != ':' || (target[2] != '\\' && target[2] != '/')) return null;

            var profile = Path.GetFullPath(profileFolder).TrimEnd('\\');
            var profileRoot = Path.GetPathRoot(profile);
            if (string.IsNullOrEmpty(profileRoot)) return null;

            var targetRoot = target[..3];
            if (string.Equals(targetRoot, profileRoot, StringComparison.OrdinalIgnoreCase)) return target;

            var profileRest = profile[profileRoot.Length..];
            var targetRest = target[3..];
            if (profileRest.Length > 0
                && targetRest.StartsWith(profileRest + "\\", StringComparison.OrdinalIgnoreCase))
                return Path.Combine(profileRoot, targetRest);

            // Scanning this PC's own system drive: other local (non-network) drive letters are the same PC's drives.
            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.Equals(profileRoot, systemRoot, StringComparison.OrdinalIgnoreCase))
            {
                var drive = new DriveInfo(targetRoot);
                if (drive.DriveType is DriveType.Fixed or DriveType.Removable && drive.IsReady) return target;
            }
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static List<string> SafeEnumerate(string folder, string pattern, IList<string> warnings, string label)
    {
        try
        {
            if (!Directory.Exists(folder)) return [];
            var options = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
            return Directory.EnumerateFiles(folder, pattern, options).ToList();
        }
        catch (Exception ex)
        {
            warnings.Add($"{label}: could not list files ({ex.GetType().Name}).");
            return [];
        }
    }
}
