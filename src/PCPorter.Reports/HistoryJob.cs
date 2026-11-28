using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Core.Snapshots;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Reports;

/// <param name="AllUsers">Read every account (live: needs administrator rights). Offline drives always show every account.</param>
/// <param name="RestorePoints">Also look for older history in existing restore points (live runs as administrator only).</param>
/// <param name="ExtraNotes">Notes from the caller (e.g. "not running as administrator").</param>
/// <param name="CurrentUserSid">Test hook: whose account a live run reads. Default: the account running PCPorter.</param>
/// <param name="RestorePointRoots">Test hook: restore points to read instead of this PC's shadow copies.</param>
/// <param name="Elevated">Test hook: whether a live run counts as administrator. Default: the real token.</param>
/// <param name="Snapshots">Test hook: who makes the temporary shadow copy for Internet Explorer history. Default: Windows (VSS).</param>
public sealed record HistoryJobOptions(bool AllUsers = false, bool RestorePoints = true, IReadOnlyList<string>? ExtraNotes = null, string? CurrentUserSid = null,
    IReadOnlyList<RestorePointRoot>? RestorePointRoots = null, bool? Elevated = null, ISnapshotProvider? Snapshots = null);

/// <param name="FolderWarnings">Always empty: the case folder's warnings are part of <see cref="HistoryScan.Warnings"/> (shown in the
/// report and counted once). Kept so callers that add the two lists still count correctly.</param>
public sealed record HistoryJobResult(string ReportPath, string CaseFolder, HistoryScan Scan, IReadOnlyList<string> FolderWarnings);

/// <summary>
/// End-to-end web history: private case folder, every browser profile of the chosen accounts read from private copies,
/// case.db rows and History.html. One unreadable profile is a warning, never the end of the run. Read-only on the
/// scanned PC.
/// </summary>
public static class HistoryJob
{
    const string ChromiumRetention = "Chrome-family browsers keep about 90 days of visits.";
    const string FirefoxRetention = "Firefox keeps visits until its history file reaches a size limit, often months to years.";
    const string WebCacheRetention = "Internet Explorer keeps 20 days of history by default (legacy Edge uses the same cache).";

    public static HistoryJobResult Run(string outRoot, ISystemSource source, HistoryJobOptions? options = null,
        IProgress<string>? progress = null, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        options ??= new HistoryJobOptions();
        var when = now ?? DateTimeOffset.UtcNow;
        // Another PC's drive: never write the case onto it (compared by real volume location, not by the text of the paths).
        if (!source.IsLive && CaseLocation.Check(outRoot, source.ReadRoot) is { IsAllowed: false } refused)
            throw new CaseLocationRejectedException(refused.Reason!);
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
        Func<string, bool?> onDisk = path => StillOnDisk(source, path);

        var liveKeys = new Dictionary<BrowserProfile, IReadOnlySet<string>?>();     // per profile: what its live history lists (null: unread)

        void Absorb(BrowserProfile profile, ProfileHistory h, string retention)
        {
            profiles.Add(profile);
            if (profile.Family != BrowserFamily.WebCache) liveKeys[profile] = h.VisitKeys;
            visits.AddRange(h.Visits); searches.AddRange(h.Searches); downloads.AddRange(h.Downloads);
            bookmarks.AddRange(h.Bookmarks); tabs.AddRange(h.Tabs); forms.AddRange(h.Forms); notes.AddRange(h.Notes);
            warnings.AddRange(h.Warnings);
            // How far back the browser itself keeps (a damaged copy's rows are mostly the browser's own list).
            var liveVisits = h.Visits.Where(v => v.Origin is Origin.Live or Origin.DamagedCopy).ToList();
            coverage.Add(new ProfileCoverage(profile, liveVisits.Count,
                liveVisits.Count == 0 ? null : liveVisits.Min(v => v.When), liveVisits.Count == 0 ? null : liveVisits.Max(v => v.When), retention));
        }

        // One profile that cannot be read is a warning; the others are still read.
        void Failed(BrowserProfile profile, Exception ex)
        {
            profiles.Add(profile);
            if (profile.Family != BrowserFamily.WebCache) liveKeys[profile] = null;
            var name = profile.Family == BrowserFamily.WebCache ? profile.Browser : $"{profile.Browser} ({profile.Name})";
            warnings.Add($"{name} for {profile.User} could not be read: {FirstLine(ex.Message)}");
            coverage.Add(new ProfileCoverage(profile, 0, null, null, "Could not be read; see the processing notes."));
        }

        try
        {
            using (SourceFiles.Confine(source.ReadRoot))
            {
                var webCaches = new List<BrowserProfile>();
                foreach (var user in users)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report($"{user.UserName}: looking for browsers");
                    foreach (var profile in BrowserProfileFinder.Find(user.UserName, user.ProfilePath!, warnings))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (profile.Family == BrowserFamily.WebCache) { webCaches.Add(profile); continue; }
                        progress?.Report($"{user.UserName}: {profile.Browser} ({profile.Name})");
                        try
                        {
                            var h = profile.Family == BrowserFamily.Firefox
                                ? FirefoxHistoryReader.Read(profile, work, onDisk, ct)
                                : ChromiumHistoryReader.Read(profile, work, onDisk, ct);
                            Absorb(profile, h, profile.Family == BrowserFamily.Firefox ? FirefoxRetention : ChromiumRetention);
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException) { Failed(profile, ex); }
                    }
                }
                if (webCaches.Count > 0)
                    ReadWebCaches(source, options, webCaches, work, onDisk, notes, progress, ct, (p, read) =>
                    {
                        try { if (read() is { } h) Absorb(p, h, WebCacheRetention); }    // null: not read, a note says why
                        catch (Exception ex) when (ex is not OperationCanceledException) { Failed(p, ex); }
                    });

                if (RestorePointRoots(source, options, notes) is { Count: > 0 } roots && users.Count > 0)
                {
                    progress?.Report($"Looking for older history in {roots.Count} restore point(s)");
                    var rp = RestorePointHistory.Read(users.Select(u => new RestorePointUser(u.UserName, u.ProfilePath!)).ToList(), liveKeys, roots, work, ct);
                    visits.AddRange(rp.Visits); notes.AddRange(rp.Notes); warnings.AddRange(rp.Warnings);
                    foreach (var p in rp.Profiles)
                    {
                        profiles.Add(p);
                        coverage.Add(new ProfileCoverage(p, 0, null, null, "No longer on this PC: found only in restore points."));
                    }
                }
            }

            // Warnings about the case folder (e.g. a drive that cannot keep it private) are shown with the rest, so the
            // report, the page and the CLI count the same warnings.
            warnings.InsertRange(0, folder.Warnings);

            // The copies are no longer needed: remove them before writing anything else, and say so if that fails.
            if (!DeleteWork(work))
                warnings.Add($"The temporary work folder {work} could not be deleted; it holds private copies of browser files. " +
                             "Delete it by hand when PCPorter is closed.");

            var scan = new HistoryScan(profiles, coverage, visits.OrderBy(v => v.When).ToList(), searches.OrderBy(s => s.When).ToList(),
                downloads.OrderBy(d => d.Started).ToList(), bookmarks, tabs, forms, notes, warnings) { TimeZone = ScannedTimeZone(source) };

            using (var db = CaseDb.Open(Path.Combine(folder.Path, "case.db")))
                db.Insert(Rows(scan));

            var version = typeof(HistoryJob).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "dev";
            var computer = source.IsLive ? Environment.MachineName : $"Drive {source.ReadRoot}";
            var meta = new ReportMeta(computer, when, version, users.Select(u => u.UserName).ToList(), options.AllUsers || !source.IsLive);
            var report = HistoryReport.WriteFile(scan, meta, folder.Path);
            return new HistoryJobResult(report, folder.Path, scan, []);
        }
        finally
        {
            DeleteWork(work);                                                   // a failed or cancelled run: best effort
        }
    }

    /// <summary>Deletes the work folder, retrying while a file in it is still briefly held (SQLite, ESE, antivirus). True when it is gone.</summary>
    static bool DeleteWork(string work)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                if (Directory.Exists(work)) Directory.Delete(work, true);
                return true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                if (attempt >= WorkDeleteAttempts) return !Directory.Exists(work);
                Thread.Sleep(100 * attempt);
            }
        }
    }

    const int WorkDeleteAttempts = 5;

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

    /// <summary>
    /// The restore points to search: the test hook's, else this PC's existing shadow copies of C: (live and elevated only;
    /// listed, never created). Otherwise a note says why none were searched.
    /// </summary>
    static IReadOnlyList<RestorePointRoot>? RestorePointRoots(ISystemSource source, HistoryJobOptions options, List<string> notes)
    {
        if (!options.RestorePoints) return null;
        if (options.RestorePointRoots is { } given) return given;
        if (!source.IsLive)
        {
            notes.Add("Restore points belong to the running PC, so they were not searched when reading another PC's drive.");
            return null;
        }
        if (!IsElevated(options))
        {
            notes.Add("PCPorter is not running as administrator, so restore points were not searched for older history.");
            return null;
        }
        var roots = RestorePointHistory.ShadowCopies();
        if (roots.Count == 0) notes.Add("No restore points of C: were found, so there was no older history to search.");
        return roots;
    }

    static bool IsElevated(HistoryJobOptions options) =>
        options.Elevated ?? new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    /// <summary>
    /// Internet Explorer / legacy Edge history (WebCacheV01.dat). Offline: read straight from the drive. Live: Windows keeps
    /// the file locked, so it is read only as administrator, from a temporary shadow copy of C: that PCPorter makes and
    /// always removes again; otherwise a note says why it was left out. <paramref name="absorb"/> runs one profile's read and
    /// keeps a failure to that profile (a warning); the read returns null when the profile was skipped with a note.
    /// </summary>
    static void ReadWebCaches(ISystemSource source, HistoryJobOptions options, List<BrowserProfile> caches, string work,
        Func<string, bool?> onDisk, List<string> notes, IProgress<string>? progress, CancellationToken ct, Action<BrowserProfile, Func<ProfileHistory?>> absorb)
    {
        if (!source.IsLive)
        {
            foreach (var p in caches)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report($"{p.User}: {p.Browser}");
                absorb(p, () => WebCacheReader.Read(p, work, onDisk, ct));
            }
            return;
        }
        if (!IsElevated(options))
        {
            notes.Add("Internet Explorer / legacy Edge history needs administrator: Windows keeps its file locked, so it was not read. " +
                      "Run PCPorter as administrator to include it.");
            return;
        }
        ISnapshot? snap = null;
        try
        {
            progress?.Report("Taking a temporary shadow copy to read Internet Explorer / legacy Edge history");
            snap = (options.Snapshots ?? new VssSnapshotProvider()).Create(@"C:\");
            using (SourceFiles.Confine(snap.DeviceRoot.TrimEnd('\\') + "\\"))
                foreach (var p in caches)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report($"{p.User}: {p.Browser}");
                    absorb(p, () =>
                    {
                        string inSnapshot;
                        try { inSnapshot = snap.Map(p.Folder); }
                        catch (ArgumentException)
                        {
                            notes.Add($"{p.Browser} history for {p.User} is not on C:, so it was not read.");
                            return null;
                        }
                        return WebCacheReader.Read(p, work, OnTheLiveDrive, ct, inSnapshot);
                    });
                }
        }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException or System.Management.ManagementException or IOException
                                      or System.Runtime.InteropServices.COMException)
        {
            notes.Add($"Internet Explorer / legacy Edge history could not be read ({FirstLine(e.Message)}).");
        }
        finally
        {
            snap?.Dispose();                                                    // the temporary shadow copy is always removed
        }

        // Whether a download is still on disk is a question about the PC now, not about the shadow copy.
        bool? OnTheLiveDrive(string path)
        {
            using (SourceFiles.Confine(source.ReadRoot)) return onDisk(path);
        }
    }

    /// <summary>The scanned PC's time zone: this PC's for a live run, else the SYSTEM hive's TimeZoneKeyName (unknown if unreadable).</summary>
    static PcTimeZone ScannedTimeZone(ISystemSource source)
    {
        if (source.IsLive) return PcTimeZone.FromWindowsId(TimeZoneInfo.Local.Id);
        try
        {
            var set = source.CurrentControlSet();
            return set is null ? PcTimeZone.Unknown
                : PcTimeZone.FromWindowsId(source.OpenHive(Hive.System)?.Open(set + @"\Control\TimeZoneInformation")?.GetString("TimeZoneKeyName"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            return PcTimeZone.Unknown;
        }
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

    /// <summary>The counts the CLI prints (and --json emits).</summary>
    public static HistorySummary Summarize(HistoryJobResult r) => new(
        r.ReportPath, r.CaseFolder, r.Scan.Profiles.Count, r.Scan.Visits.Count, r.Scan.Searches.Count, r.Scan.Downloads.Count,
        r.Scan.Visits.Count(v => v.Origin is Origin.Carved or Origin.RestorePoint or Origin.RestorePointCopy), r.Scan.Notes.Count, r.Scan.Warnings.Count + r.FolderWarnings.Count,
        r.Scan.Bookmarks.Count, r.Scan.Tabs.Count, r.Scan.Forms.Count);

    /// <summary>0 when everything was read, 1 (partial) when anything was skipped with a warning.</summary>
    public static int ExitCode(HistoryJobResult r) =>
        r.Scan.Warnings.Count + r.FolderWarnings.Count > 0 ? PCPorter.Core.Cli.ExitCodes.Partial : PCPorter.Core.Cli.ExitCodes.Ok;
}

public sealed record HistorySummary(string Report, string CaseFolder, int Profiles, int Visits, int Searches, int Downloads,
    int Recovered, int Notes, int Warnings, int Bookmarks, int Tabs, int Forms);
