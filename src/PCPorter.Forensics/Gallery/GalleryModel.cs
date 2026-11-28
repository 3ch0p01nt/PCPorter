using PCPorter.Forensics.Images;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Gallery;

/// <summary>
/// Exists = present now; Deleted = its folder is readable and it is gone; FolderGone = the folder that held it is
/// no longer there (moved, renamed, deleted, or another drive now uses that letter: not proof the file was deleted);
/// Unreachable = drive missing or a different disk, access denied or network path (we cannot tell);
/// Unknown = no original path recorded.
/// </summary>
public enum OriginalStatus { Exists, Deleted, Unreachable, Unknown, FolderGone }

/// <summary>
/// One stored copy of an image at a given size. <see cref="File"/> is named by content hash, so identical images are
/// stored once. <see cref="RestorePoint"/> is set when this copy came from a restore point (its creation time).
/// </summary>
public sealed record GalleryImage(string SizeClass, int Width, int Height, string File, ImageFormat Format, bool FoundInFreeSpace,
    DateTimeOffset? RestorePoint = null);

/// <summary>
/// "Displayed between After and Before". Each source line says what the time is, so nothing is presented
/// as a viewing time unless it is one.
/// </summary>
public sealed record DateWindow(DateTimeOffset? After, DateTimeOffset? Before, string Confidence, IReadOnlyList<string> Sources);

/// <summary>One picture in the gallery, from any source (thumbnail cache, browser cache, screenshots, recent files).</summary>
public sealed record GalleryItem(
    string Id,
    string Kind,                       // thumbnail | icon | web | screenshot | opened
    string Source,                     // plain words, e.g. "File Explorer thumbnails", "Edge cache (Default)"
    EvidenceLevel Evidence,
    string User,
    string? CacheId,
    string? OriginalPath,
    string? Url,
    OriginalStatus Status,
    bool FoundInFreeSpace,
    GalleryImage? Best,
    IReadOnlyList<GalleryImage> Images,
    DateWindow? Dates,
    string? Note,
    int? DupGroup = null,
    IReadOnlyList<DateTimeOffset>? RestorePoints = null,   // creation times of the restore points that also held this entry
    bool OnlyInRestorePoints = false)                      // the live cache no longer has it
{
    public bool HasImage => Best is not null;
}

public sealed record CacheFileSummary(string User, string File, int Version, int Images, int Empty, int Warnings);

/// <summary>Headline counts for the app and command line. Original-file counts are for thumbnails only.</summary>
public sealed record GallerySummary(
    int Items, int Thumbnails, int DeletedOriginals, int FolderGone, int Unreachable, int ExistingOriginals, int UnknownOriginals,
    int WithoutPicture, int FoundInFreeSpace, int OnlyInRestorePoints, int Web, int Screenshots, int Opened, int Icons)
{
    public static GallerySummary From(IReadOnlyList<GalleryItem> items)
    {
        var thumbs = items.Where(i => i.Kind == "thumbnail").ToList();
        int Thumbs(OriginalStatus s) => thumbs.Count(i => i.Status == s);
        int Kind(string k) => items.Count(i => i.Kind == k);
        return new GallerySummary(items.Count, thumbs.Count, Thumbs(OriginalStatus.Deleted), Thumbs(OriginalStatus.FolderGone),
            Thumbs(OriginalStatus.Unreachable), Thumbs(OriginalStatus.Exists), Thumbs(OriginalStatus.Unknown),
            items.Count(i => !i.HasImage), items.Count(i => i.FoundInFreeSpace),
            thumbs.Count(i => i.OnlyInRestorePoints),
            Kind("web"), Kind("screenshot"), Kind("opened"), Kind("icon"));
    }
}

public sealed record GalleryScanResult(
    IReadOnlyList<GalleryItem> Items, IReadOnlyList<CacheFileSummary> CacheFiles,
    IReadOnlyList<string> Warnings, IReadOnlyList<string> Notes)
{
    public GallerySummary Summary => GallerySummary.From(Items);
}
