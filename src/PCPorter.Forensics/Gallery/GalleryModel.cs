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

/// <summary>One stored copy of an image at a given size. <see cref="File"/> is named by content hash, so identical images are stored once.</summary>
public sealed record GalleryImage(string SizeClass, int Width, int Height, string File, ImageFormat Format, bool FoundInFreeSpace);

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
    int? DupGroup = null)
{
    public bool HasImage => Best is not null;
}

public sealed record CacheFileSummary(string User, string File, int Version, int Images, int Empty, int Warnings);

public sealed record GalleryScanResult(
    IReadOnlyList<GalleryItem> Items, IReadOnlyList<CacheFileSummary> CacheFiles,
    IReadOnlyList<string> Warnings, IReadOnlyList<string> Notes);
