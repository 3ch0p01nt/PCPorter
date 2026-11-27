namespace PCPorter.Forensics.BrowserHistory;

/// <summary>How a page was reached, simplified from the browser's own transition types.</summary>
public enum VisitHow { Link, Typed, Bookmark, Redirect, Reload, Generated, FormSubmit, Other }

/// <summary>Where a row came from: the live database (including its write-ahead log), carved free space, or a restore point.</summary>
public enum Origin { Live, Carved, RestorePoint }

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
}

/// <summary>Everything found for a web history report.</summary>
public sealed record HistoryScan(
    IReadOnlyList<BrowserProfile> Profiles, IReadOnlyList<ProfileCoverage> Coverage,
    IReadOnlyList<Visit> Visits, IReadOnlyList<Search> Searches, IReadOnlyList<Download> Downloads,
    IReadOnlyList<Bookmark> Bookmarks, IReadOnlyList<OpenTab> Tabs, IReadOnlyList<FormEntry> Forms,
    IReadOnlyList<string> Notes, IReadOnlyList<string> Warnings);
