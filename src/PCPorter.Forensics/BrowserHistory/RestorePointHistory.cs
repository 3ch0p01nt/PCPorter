using PCPorter.Collectors.Sources;
using PCPorter.Core.Snapshots;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>One restore point: the root its files are read under, when it was made, and how a path on the PC maps into it (null: not in it).</summary>
public sealed record RestorePointRoot(string Root, DateTimeOffset Created, Func<string, string?> Map);

/// <summary>
/// Older history from restore points (existing shadow copies of C:): each browser profile's history database as it was
/// then, read from a private copy, keeping only visits that are not in the history found already (same address and
/// time to the second). Read-only: restore points are listed, never created. Each restore point's files are read only
/// inside that restore point.
/// </summary>
public static class RestorePointHistory
{
    public sealed record Result(IReadOnlyList<Visit> Visits, IReadOnlyList<string> Notes, IReadOnlyList<string> Warnings);

    public static Result Read(IReadOnlyList<BrowserProfile> profiles, IEnumerable<Visit> known, IReadOnlyList<RestorePointRoot> roots,
        string workFolder, CancellationToken ct = default)
    {
        var seen = known.Select(Key).ToHashSet();
        var found = new List<Visit>();
        var warnings = new List<string>();
        foreach (var root in roots.OrderBy(r => r.Created))
        {
            var label = $"restore point {root.Created:yyyy-MM-dd}";
            using (SourceFiles.Confine(root.Root))
            {
                foreach (var profile in profiles)
                {
                    ct.ThrowIfCancellationRequested();
                    if (profile.Family == BrowserFamily.WebCache) continue;
                    string? folder;
                    try { folder = root.Map(profile.Folder); }
                    catch (ArgumentException) { continue; }                    // on another drive than the restore point's
                    if (folder is null || !File.Exists(Path.Combine(folder, profile.Family == BrowserFamily.Firefox ? "places.sqlite" : "History"))) continue;
                    try
                    {
                        var copy = profile with { Folder = folder };
                        var visits = profile.Family == BrowserFamily.Firefox
                            ? FirefoxHistoryReader.ReadVisitsOnly(copy, workFolder, ct)
                            : ChromiumHistoryReader.ReadVisitsOnly(copy, workFolder, ct);
                        foreach (var v in visits)
                            if (seen.Add(Key(v))) found.Add(v with { Profile = profile, Origin = Origin.RestorePoint, OriginNote = label });
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        warnings.Add($"{profile.Browser} ({profile.Name}) for {profile.User}: the copy in the {label} could not be read: {e.Message.Split('\n')[0].Trim()}");
                    }
                }
            }
        }
        var notes = new List<string>
        {
            $"{roots.Count} restore point{(roots.Count == 1 ? " was" : "s were")} searched for older browser history: " +
            $"{found.Count} older visit{(found.Count == 1 ? " was" : "s were")} found that the browsers no longer list (marked \"Recovered (restore point)\").",
        };
        return new Result(found.OrderBy(v => v.When).ThenBy(v => v.Url, StringComparer.Ordinal).ToList(), notes, warnings);
    }

    static (string Url, long Second) Key(Visit v) => (v.Url, v.When.ToUnixTimeSeconds());

    /// <summary>The existing restore points (shadow copies) of C:, oldest first. Needs administrator rights; lists only, never creates.</summary>
    public static IReadOnlyList<RestorePointRoot> ShadowCopies() =>
        VssSnapshotProvider.ListExisting(@"C:\").Select(s => new RestorePointRoot(s.DeviceObject + @"\", s.Created,
            p => p.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase) ? VssSnapshotProvider.MapPath(s.DeviceObject, @"C:\", p) : null)).ToList();
}
