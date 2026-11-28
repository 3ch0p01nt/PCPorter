using System.Globalization;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;

namespace PCPorter.Reports;

/// <summary>What the person asked for on the Web history page or the <c>history</c> command.</summary>
/// <param name="OutRoot">Folder to create the case folder in.</param>
/// <param name="OfflineRoot">Another PC's Windows drive (for example D:\), or null for this PC.</param>
/// <param name="AllUsers">Every account (this PC: administrator only; another PC's drive: always).</param>
/// <param name="RestorePoints">Also search this PC's existing restore points (administrator only).</param>
public sealed record HistoryRequest(string OutRoot, string? OfflineRoot, bool AllUsers, bool RestorePoints);

/// <summary>
/// The shared, UI-free half of the Web history page and the CLI: the save-folder rules, the options (with the
/// "not administrator" note), opening this PC or another PC's drive, and the one-sentence result.
/// </summary>
public static class HistorySetup
{
    public const string NotAdminNote = "PCPorter is not running as administrator, so only your own account was read. " +
                                       "Run it as administrator to include the other accounts (ask them first).";

    /// <summary>
    /// Why the case cannot be saved there (cloud-synced, network, or on the drive being checked, however either is
    /// reached: subst letter, mount point, \\?\ path), or null when it can.
    /// </summary>
    public static string? SaveFolderProblem(string outRoot, string? offlineRoot)
    {
        var check = CaseLocation.Check(outRoot, offlineRoot);
        return check.IsAllowed ? null : check.Reason;
    }

    /// <summary>Job options for a request. "All accounts" on this PC without administrator becomes your own account plus a note.</summary>
    public static HistoryJobOptions Options(HistoryRequest request, bool elevated)
    {
        var notes = new List<string>();
        var all = request.AllUsers;
        if (all && request.OfflineRoot is null && !elevated)
        {
            notes.Add(NotAdminNote);
            all = false;
        }
        return new HistoryJobOptions(all, request.RestorePoints, notes, Elevated: elevated);
    }

    /// <summary>Checks the save folder, opens this PC or the other PC's drive and runs the history job.</summary>
    /// <exception cref="CaseLocationRejectedException">The save folder is not allowed.</exception>
    public static HistoryJobResult Run(HistoryRequest request, bool elevated, IProgress<string>? progress = null,
        DateTimeOffset? now = null, CancellationToken ct = default)
    {
        if (SaveFolderProblem(request.OutRoot, request.OfflineRoot) is { } problem) throw new CaseLocationRejectedException(problem);
        using ISystemSource source = request.OfflineRoot is null ? new LiveSource() : new OfflineSource(request.OfflineRoot);
        return HistoryJob.Run(request.OutRoot, source, Options(request, elevated), progress, now, ct);
    }

    /// <summary>One sentence for the page: what was found.</summary>
    public static string Describe(HistorySummary s, IFormatProvider? culture = null)
    {
        culture ??= CultureInfo.CurrentCulture;
        if (s.Profiles == 0) return "No web browser history was found.";
        string N(int n, string one, string many) => string.Format(culture, "{0:N0} {1}", n, n == 1 ? one : many);
        var visits = N(s.Visits, "visit", "visits") +
                     (s.Recovered > 0 ? string.Format(culture, " ({0:N0} recovered from leftover data or restore points: deleted, or older copies)", s.Recovered) : "");
        return $"{N(s.Profiles, "browser profile", "browser profiles")}: {visits}, {N(s.Searches, "search", "searches")}, " +
               $"{N(s.Downloads, "download", "downloads")}, {N(s.Bookmarks, "bookmark", "bookmarks")}, {N(s.Tabs, "tab", "tabs")}, " +
               $"{N(s.Forms, "form entry", "form entries")}.";
    }
}
