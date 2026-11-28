namespace PCPorter.Forensics.Images;

/// <summary>What a piece of image evidence proves. Shown to the user in plain words.</summary>
public enum EvidenceLevel
{
    /// <summary>Windows drew a thumbnail of it (Explorer thumbnail cache).</summary>
    Displayed,
    /// <summary>The file was opened in an app (recent files, shortcuts, Jump Lists).</summary>
    Opened,
    /// <summary>A web page loaded it (browser cache).</summary>
    LoadedByWebPage,
    /// <summary>It was on screen (screenshot, snip).</summary>
    OnScreen,
    /// <summary>It was saved/received but not necessarily viewed.</summary>
    Downloaded,
}

/// <summary>
/// One image-related observation from any source. Sources fill what they know and leave the rest null.
/// <see cref="TimeMeaning"/> says what the time fields mean, e.g. "first stored in Edge cache" -
/// never present a time as a viewing time unless the source proves it.
/// </summary>
public sealed record ImageEvidence(
    string Source,                       // e.g. "Edge cache (Default profile)", "Screenshots folder", "Recent files"
    EvidenceLevel Evidence,
    string User,
    string? OriginalPath,                // file path on the scanned PC, if known
    string? Url,                         // web address, for browser caches
    DateTimeOffset? FirstSeenUtc,
    DateTimeOffset? LastSeenUtc,
    string? TimeMeaning,
    byte[]? ImageBytes,                  // null when the source only records a path (e.g. recent files)
    string? ContentType = null,          // e.g. "image/png"
    string? Note = null,
    uint? VolumeSerial = null);          // serial of the volume the original was on, when the record saved it (shortcuts)

/// <summary>Context passed to every image source.</summary>
public sealed record ImageSourceContext(
    string User,
    string ProfileFolder,                // e.g. C:\Users\bob (or the same folder on an offline drive)
    IList<string> Warnings,
    IList<string>? Notes = null);        // report notes (not problems), e.g. "3 pictures are stored only online"

/// <summary>A source of image evidence (browser cache, screenshots, recent files...). Must be read-only.</summary>
public interface IImageEvidenceSource
{
    string Name { get; }
    IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default);
}
