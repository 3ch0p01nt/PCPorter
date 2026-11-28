using PCPorter.Collectors.Sources;
using PCPorter.Core.Snapshots;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>One restore point: the root its files are read under, when it was made, and how a path on the PC maps into it (null: not in it).</summary>
public sealed record RestorePointRoot(string Root, DateTimeOffset Created, Func<string, string?> Map);

/// <summary>An account whose folder is searched inside each restore point: its name and its profile folder on the PC.</summary>
public sealed record RestorePointUser(string User, string ProfileFolder);

/// <summary>
/// Older history from restore points (existing shadow copies of C:). Inside each restore point, every account's folder
/// is searched for browser profiles (so profiles deleted since are found too), and each history database is read
/// from a private copy. Visits of a profile whose live history was read are kept only when that list does not have
/// them ("no longer listed"); for any other profile (not read live, or gone from the PC) the visits are kept as
/// "restore point copy", since nothing says whether the browser still lists them. Each visit appears once per
/// profile. Read-only: restore points are listed, never created; each one's files are read only inside it.
/// </summary>
public static class RestorePointHistory
{
    /// <param name="Profiles">Profiles found only in restore points (no longer on the PC), shown as they were on the PC.</param>
    public sealed record Result(IReadOnlyList<Visit> Visits, IReadOnlyList<string> Notes, IReadOnlyList<string> Warnings,
        IReadOnlyList<BrowserProfile> Profiles);

    public const string NoLongerListed = "no longer in the browser's history";
    public const string CopyLabel = "Restore point copy";

    /// <param name="liveKeys">The profiles found on the PC, each with its <see cref="ProfileHistory.VisitKeys"/> (null when its live history could not be read).</param>
    /// <param name="zone">Time zone for the restore points' dates in labels; default: this PC's.</param>
    public static Result Read(IReadOnlyList<RestorePointUser> users, IReadOnlyDictionary<BrowserProfile, IReadOnlySet<string>?> liveKeys,
        IReadOnlyList<RestorePointRoot> roots, string workFolder, CancellationToken ct = default, TimeZoneInfo? zone = null)
    {
        zone ??= TimeZoneInfo.Local;
        var seen = new HashSet<(string Profile, string Key)>();
        var found = new List<Visit>();
        var warnings = new List<string>();
        var extra = new Dictionary<string, BrowserProfile>(StringComparer.OrdinalIgnoreCase);
        int claimed = 0, copies = 0;
        foreach (var root in roots.OrderBy(r => r.Created))
        {
            var when = TimeZoneInfo.ConvertTime(root.Created, zone);
            var label = $"restore point {when:yyyy-MM-dd HH:mm}";
            using (SourceFiles.Confine(root.Root))
            {
                foreach (var user in users)
                {
                    ct.ThrowIfCancellationRequested();
                    string? home;
                    try { home = root.Map(user.ProfileFolder); }
                    catch (ArgumentException) { continue; }                      // on another drive than the restore point's
                    if (home is null) continue;
                    if (!SourceFiles.IsInside(home))
                    {
                        warnings.Add($"{user.User}: in the {label}, the account folder leads outside the restore point, so it was not read.");
                        continue;
                    }
                    var findWarnings = new List<string>();
                    foreach (var copy in BrowserProfileFinder.Find(user.User, home, findWarnings))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (copy.Family == BrowserFamily.WebCache) continue;
                        var onPc = OnThePc(copy, home, user.ProfileFolder);
                        var profile = liveKeys.Keys.FirstOrDefault(p => p.Family == copy.Family && p.Browser == copy.Browser
                                          && string.Equals(p.User, copy.User, StringComparison.OrdinalIgnoreCase)
                                          && string.Equals(p.Folder, onPc.Folder, StringComparison.OrdinalIgnoreCase));
                        if (profile is null && !extra.TryGetValue(onPc.Folder, out profile)) extra[onPc.Folder] = profile = onPc;
                        var listed = liveKeys.GetValueOrDefault(profile);
                        try
                        {
                            var visits = copy.Family == BrowserFamily.Firefox
                                ? FirefoxHistoryReader.ReadVisitsOnly(copy, workFolder, ct)
                                : ChromiumHistoryReader.ReadVisitsOnly(copy, workFolder, ct);
                            foreach (var (v, key) in visits)
                            {
                                if (listed is not null && listed.Contains(key)) continue;
                                if (!seen.Add((profile.Folder.ToUpperInvariant() + "|" + profile.Browser, key))) continue;
                                found.Add(v with { Profile = profile, Origin = listed is not null ? Origin.RestorePoint : Origin.RestorePointCopy,
                                                   OriginNote = listed is not null ? $"{label}, {NoLongerListed}" : label });
                                if (listed is not null) claimed++; else copies++;
                            }
                        }
                        catch (Exception e) when (e is not OperationCanceledException)
                        {
                            warnings.Add($"{profile.Browser} ({profile.Name}) for {profile.User}: the copy in the {label} could not be read: {e.Message.Split('\n')[0].Trim()}");
                        }
                    }
                    warnings.AddRange(findWarnings.Select(w => $"In the {label}: {w}"));
                }
            }
        }
        var notes = new List<string>
        {
            $"{roots.Count} restore point{(roots.Count == 1 ? " was" : "s were")} searched for older browser history: " +
            $"{claimed} older visit{(claimed == 1 ? " was" : "s were")} found that the browsers no longer list (marked \"Recovered (restore point)\").",
        };
        if (copies > 0)
            notes.Add($"{copies} visit{(copies == 1 ? " was" : "s were")} found in restore point copies of browser profiles whose current history " +
                      $"could not be read or that are no longer on this PC (marked \"{CopyLabel}\"); they may still be in the browser's history.");
        return new Result(found.OrderBy(v => v.When).ThenBy(v => v.Url, StringComparer.Ordinal).ToList(), notes, warnings, [.. extra.Values]);
    }

    /// <summary>The profile as it would be on the PC: its folder inside the restore point moved back under the account's real folder.</summary>
    static BrowserProfile OnThePc(BrowserProfile copy, string homeInCopy, string home)
    {
        var rest = copy.Folder.StartsWith(homeInCopy, StringComparison.OrdinalIgnoreCase) ? copy.Folder[homeInCopy.Length..].TrimStart('\\') : copy.Folder;
        return copy with { Folder = Path.Combine(home, rest) };
    }

    /// <summary>The existing restore points (shadow copies) of C:, oldest first. Needs administrator rights; lists only, never creates.</summary>
    public static IReadOnlyList<RestorePointRoot> ShadowCopies() =>
        VssSnapshotProvider.ListExisting(@"C:\").Select(s => new RestorePointRoot(s.DeviceObject + @"\", s.Created,
            p => p.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase) ? VssSnapshotProvider.MapPath(s.DeviceObject, @"C:\", p) : null)).ToList();
}
