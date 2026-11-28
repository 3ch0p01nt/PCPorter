namespace PCPorter.Forensics.BrowserHistory;

/// <summary>How a page was reached, simplified from the browser's own transition types.</summary>
public enum VisitHow { Link, Typed, Bookmark, Redirect, Reload, Generated, FormSubmit, Other }

/// <summary>
/// Where a row came from: the live database (including its write-ahead log), leftover data inside the file (carved),
/// a restore point (a visit the live history no longer lists), the raw bytes of a copy SQLite could not open
/// (DamagedCopy: mostly rows the browser still lists), or a restore point's copy of a profile that could not be
/// compared with the live history (RestorePointCopy: not read live, or no longer on the PC).
/// </summary>
public enum Origin { Live, Carved, RestorePoint, DamagedCopy, RestorePointCopy }

public enum DownloadState { InProgress, Complete, Cancelled, Interrupted, Unknown }

public enum TabState { Open, RecentlyClosed }

// All times are UTC. URLs, titles and form values are already masked by Redactor.

public sealed record Visit(BrowserProfile Profile, string Url, string? Title, DateTimeOffset When, VisitHow How,
    long DurationSeconds, Origin Origin = Origin.Live, string? OriginNote = null);

public sealed record Search(BrowserProfile Profile, string Terms, string Engine, DateTimeOffset When, Origin Origin = Origin.Live);

/// <param name="StillOnDisk">Whether the saved file is still at its path on the scanned PC; null when that cannot be checked.</param>
public sealed record Download(BrowserProfile Profile, string Url, string? Referrer, string TargetPath, DateTimeOffset? Started,
    long Bytes, DownloadState State, bool? StillOnDisk);

public sealed record Bookmark(BrowserProfile Profile, string Title, string Url, string Folder, DateTimeOffset? Added);

public sealed record OpenTab(BrowserProfile Profile, string Url, string? Title, int Window, TabState State, DateTimeOffset? LastActive);

public sealed record FormEntry(BrowserProfile Profile, string Field, string Value, int Count, DateTimeOffset? First, DateTimeOffset? Last);

/// <summary>How far back one profile's history goes, with a note on how long that browser keeps it.</summary>
public sealed record ProfileCoverage(BrowserProfile Profile, int Visits, DateTimeOffset? Earliest, DateTimeOffset? Latest, string Note);

/// <summary>What one reader found in one profile.</summary>
public sealed record ProfileHistory(
    IReadOnlyList<Visit> Visits, IReadOnlyList<Search> Searches, IReadOnlyList<Download> Downloads,
    IReadOnlyList<Bookmark> Bookmarks, IReadOnlyList<OpenTab> Tabs, IReadOnlyList<FormEntry> Forms, IReadOnlyList<string> Notes)
{
    public static ProfileHistory Empty { get; } = new([], [], [], [], [], [], []);

    /// <summary>Parts of the profile that could not be read (the rest was).</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>
    /// <see cref="VisitKey"/> of every visit in the browser's own history list, or null when that list could not be read
    /// (then nothing can be said to be "no longer listed"). Memory only; never written anywhere.
    /// </summary>
    public IReadOnlySet<string>? VisitKeys { get; init; }

    /// <summary>
    /// A visit's identity for comparing copies of one profile: a hash of the address BEFORE masking (two addresses
    /// that differ only in a masked secret stay different, and the secret is not kept) and the time to the second.
    /// </summary>
    public static string VisitKey(string rawUrl, DateTimeOffset when) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rawUrl)), 0, 16) + "|" + when.ToUnixTimeSeconds();
}

/// <summary>Everything found for a web history report.</summary>
public sealed record HistoryScan(
    IReadOnlyList<BrowserProfile> Profiles, IReadOnlyList<ProfileCoverage> Coverage,
    IReadOnlyList<Visit> Visits, IReadOnlyList<Search> Searches, IReadOnlyList<Download> Downloads,
    IReadOnlyList<Bookmark> Bookmarks, IReadOnlyList<OpenTab> Tabs, IReadOnlyList<FormEntry> Forms,
    IReadOnlyList<string> Notes, IReadOnlyList<string> Warnings)
{
    /// <summary>The time zone the scanned PC was set to (the report shows times in the viewer's zone and names both).</summary>
    public PcTimeZone TimeZone { get; init; } = PcTimeZone.Unknown;
}

/// <summary>A PC's time zone setting: Windows id (e.g. "W. Europe Standard Time"), IANA id when known, and a display name.</summary>
public sealed record PcTimeZone(string? WindowsId, string? Iana, string Display)
{
    public static PcTimeZone Unknown { get; } = new(null, null, "unknown");

    /// <summary>From a Windows time zone id (the SYSTEM hive's TimeZoneKeyName); unknown when empty.</summary>
    public static PcTimeZone FromWindowsId(string? id)
    {
        id = id?.Trim('\0', ' ');
        if (string.IsNullOrEmpty(id)) return Unknown;
        var iana = TimeZoneInfo.TryConvertWindowsIdToIanaId(id, out var i) ? i : null;
        string display;
        try { display = TimeZoneInfo.FindSystemTimeZoneById(id).DisplayName; }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { display = id; }
        return new(id, iana, display);
    }
}
