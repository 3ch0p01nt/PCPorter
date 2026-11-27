using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Reports;

/// <param name="AllUsers">Read every account (live: needs administrator rights). Offline drives always show every account.</param>
/// <param name="RestorePoints">Also look in existing restore points (read in a later version; kept for the CLI and app).</param>
/// <param name="ExtraNotes">Notes from the caller (e.g. "not running as administrator").</param>
/// <param name="CurrentUserSid">Test hook: whose account a live run reads. Default: the account running PCPorter.</param>
public sealed record HistoryJobOptions(bool AllUsers = false, bool RestorePoints = true, IReadOnlyList<string>? ExtraNotes = null, string? CurrentUserSid = null);

public sealed record HistoryJobResult(string ReportPath, string CaseFolder, HistoryScan Scan, IReadOnlyList<string> FolderWarnings);

/// <summary>
/// End-to-end web history: private case folder, every browser profile of the chosen accounts read from private copies,
/// case.db rows and History.html. One unreadable profile is a warning, never the end of the run. Read-only on the
/// scanned PC.
/// </summary>
public static class HistoryJob
{
    const string ChromiumRetention = "Chrome-family browsers keep about 90 days of visits.";

    public static HistoryJobResult Run(string outRoot, ISystemSource source, HistoryJobOptions? options = null,
        IProgress<string>? progress = null, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        options ??= new HistoryJobOptions();
        var when = now ?? DateTimeOffset.UtcNow;
        var folder = CaseFolder.Create(outRoot, when);
        var work = Path.Combine(folder.Path, "work");
        CaseFolder.CreatePrivate(work);

        var notes = new List<string>(source.Notes);
        notes.AddRange(options.ExtraNotes ?? []);
        var warnings = new List<string>();
        var profiles = new List<BrowserProfile>();
        var coverage = new List<ProfileCoverage>();
        var visits = new List<Visit>();
        var searches = new List<Search>();
        var downloads = new List<Download>();
        var bookmarks = new List<Bookmark>();
        var tabs = new List<OpenTab>();
        var forms = new List<FormEntry>();
        var users = Users(source, options, notes);

        try
        {
            using (SourceFiles.Confine(source.ReadRoot))
            {
                var later = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var user in users)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report($"{user.UserName}: looking for browsers");
                    foreach (var profile in BrowserProfileFinder.Find(user.UserName, user.ProfilePath!, warnings))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (profile.Family != BrowserFamily.Chromium) { later.Add(profile.Browser); continue; }
                        profiles.Add(profile);
                        progress?.Report($"{user.UserName}: {profile.Browser} ({profile.Name})");
                        try
                        {
                            var h = ChromiumHistoryReader.Read(profile, work, path => StillOnDisk(source, path), ct);
                            visits.AddRange(h.Visits); searches.AddRange(h.Searches); downloads.AddRange(h.Downloads);
                            bookmarks.AddRange(h.Bookmarks); tabs.AddRange(h.Tabs); forms.AddRange(h.Forms); notes.AddRange(h.Notes);
                            coverage.Add(new ProfileCoverage(profile, h.Visits.Count,
                                h.Visits.Count == 0 ? null : h.Visits.Min(v => v.When), h.Visits.Count == 0 ? null : h.Visits.Max(v => v.When), ChromiumRetention));
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            warnings.Add($"{profile.Browser} ({profile.Name}) for {user.UserName} could not be read: {FirstLine(ex.Message)}");
                            coverage.Add(new ProfileCoverage(profile, 0, null, null, "Could not be read; see the processing notes."));
                        }
                    }
                }
                foreach (var b in later)
                    notes.Add($"{b} history was found but is not read by this version of PCPorter.");
            }

            var scan = new HistoryScan(profiles, coverage, visits.OrderBy(v => v.When).ToList(), searches.OrderBy(s => s.When).ToList(),
                downloads.OrderBy(d => d.Started).ToList(), bookmarks, tabs, forms, notes, warnings);

            using (var db = CaseDb.Open(Path.Combine(folder.Path, "case.db")))
                db.Insert(Rows(scan));

            var version = typeof(HistoryJob).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev";
            var computer = source.IsLive ? Environment.MachineName : $"Drive {source.ReadRoot}";
            var meta = new ReportMeta(computer, when, version, users.Select(u => u.UserName).ToList(), options.AllUsers || !source.IsLive);
            var report = HistoryReport.WriteFile(scan, meta, folder.Path);
            return new HistoryJobResult(report, folder.Path, scan, folder.Warnings);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>Live: the person running PCPorter (every account with AllUsers). Offline: every account. Unavailable profiles become notes.</summary>
    static List<UserProfile> Users(ISystemSource source, HistoryJobOptions options, List<string> notes)
    {
        IEnumerable<UserProfile> chosen = source.Users;
        if (source.IsLive && !options.AllUsers)
        {
            var sid = options.CurrentUserSid ?? WindowsIdentity.GetCurrent().User?.Value;
            var me = source.Users.Where(u => string.Equals(u.Sid, sid, StringComparison.OrdinalIgnoreCase)).ToList();
            if (me.Count == 0 && options.CurrentUserSid is null)
            {
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                me = [new UserProfile(sid ?? "", Environment.UserName, home, null, home)];
            }
            chosen = me;
        }
        var list = new List<UserProfile>();
        foreach (var u in chosen)
        {
            if (u.ProfilePath is null) notes.Add($"{u.UserName}: {u.Unavailable ?? "the profile folder could not be found."}");
            else list.Add(u);
        }
        return list;
    }

    /// <summary>Is a downloaded file still at its path on the scanned PC? Null when that cannot be checked.</summary>
    static bool? StillOnDisk(ISystemSource source, string pathOnScannedPc)
    {
        if (source.MapPath(pathOnScannedPc) is not { } mapped) return null;
        try
        {
            if (File.Exists(mapped)) return SourceFiles.IsInside(mapped) ? true : null;
            return Directory.Exists(Path.GetDirectoryName(mapped)) ? false : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    static IEnumerable<Artifact> Rows(HistoryScan scan)
    {
        static string Src(BrowserProfile p) => $"{p.Browser}/{p.Name}";
        foreach (var v in scan.Visits)
            yield return new Artifact(v.When, "WebHistory.Visit", Src(v.Profile), "Visit", v.Profile.User, v.How.ToString(), v.Url,
                JsonSerializer.Serialize(new { v.Title, v.DurationSeconds, Origin = v.Origin.ToString(), v.OriginNote }), Confidence.Ran);
        foreach (var s in scan.Searches)
            yield return new Artifact(s.When, "WebHistory.Search", Src(s.Profile), "Search", s.Profile.User, s.Engine, s.Terms,
                JsonSerializer.Serialize(new { Origin = s.Origin.ToString() }), Confidence.Ran);
        foreach (var d in scan.Downloads)
            yield return new Artifact(d.Started, "WebHistory.Download", Src(d.Profile), "Download", d.Profile.User, d.State.ToString(), d.Url,
                JsonSerializer.Serialize(new { d.TargetPath, d.Bytes, d.Referrer, d.StillOnDisk }), Confidence.Ran);
        foreach (var b in scan.Bookmarks)
            yield return new Artifact(b.Added, "WebHistory.Bookmark", Src(b.Profile), "Bookmark", b.Profile.User, "Bookmarked", b.Url,
                JsonSerializer.Serialize(new { b.Title, b.Folder }), Confidence.Existed);
        foreach (var t in scan.Tabs)
            yield return new Artifact(t.LastActive, "WebHistory.Tab", Src(t.Profile), "Tab", t.Profile.User, t.State.ToString(), t.Url,
                JsonSerializer.Serialize(new { t.Title, t.Window }), Confidence.Existed);
        foreach (var f in scan.Forms)
            yield return new Artifact(f.Last, "WebHistory.Form", Src(f.Profile), "Form", f.Profile.User, "Entered", f.Field,
                JsonSerializer.Serialize(new { f.Value, f.Count, f.First }), Confidence.Ran);
    }

    static string FirstLine(string message) => message.Split('\n')[0].Trim();
}
