using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Tier 3 for the web history report: an offline run (the same path as the app page and <c>history --offline</c>) over
/// bob's planted Chrome, Firefox and Internet Explorer history on the fake old-PC drive. Checks a golden summary, the
/// planted items (including deleted visits), that no secret leaks, that the drive is unchanged, and (spy) that the
/// password, cookie and key files are never opened.
/// </summary>
public sealed class HistoryOldPcTests : IDisposable
{
    readonly OldPcDrive _drive = OldPcDrive.Create();
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-regress-history").FullName;
    static readonly DateTimeOffset FixedNow = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);

    public void Dispose()
    {
        _drive.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_out, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    HistoryJobResult Run() => HistorySetup.Run(new HistoryRequest(_out, _drive.Root, AllUsers: false, RestorePoints: true), elevated: false, now: FixedNow);

    [Fact]
    public void Offline_history_matches_golden_summary() => Golden.Check("history-oldpc", Summary(Run()));

    [Fact]
    public void Planted_history_is_found()
    {
        var r = Run();
        var s = r.Scan;
        Assert.Empty(s.Warnings);
        Assert.Equal(["Firefox", "Google Chrome", "Internet Explorer / Edge (legacy)"], s.Coverage.Select(c => c.Profile.Browser).Order(StringComparer.Ordinal));
        Assert.Equal("Bob", s.Profiles.Single(p => p.Browser == "Google Chrome").Name);                     // name from Local State
        Assert.All(s.Profiles, p => Assert.Equal("bob", p.User));

        var chrome = s.Visits.Where(v => v.Profile.Browser == "Google Chrome").ToList();
        Assert.Contains(chrome, v => v.Url == "https://news.example/" && v.How == VisitHow.Typed && v.When == OldPcDrive.HistoryT0 && v.DurationSeconds == 30);
        Assert.Contains(chrome, v => v.Url == "https://track.example/r" && v.How == VisitHow.Redirect);
        Assert.Contains(chrome, v => v.Url == "https://landing.example/offer" && v.How == VisitHow.Link);
        var deleted = Enumerable.Range(0, OldPcDrive.Fillers).Where(OldPcDrive.FillerDeleted)
            .Select(i => $"{OldPcDrive.FillerTime(i):O} {OldPcDrive.FillerUrl(i)}").ToList();
        Assert.Equal(deleted, chrome.Where(v => v.Origin == Origin.Carved).Select(v => $"{v.When:O} {v.Url}").Order(StringComparer.Ordinal));  // exactly the deleted ones
        Assert.DoesNotContain(chrome, v => v.Origin == Origin.Live && deleted.Any(d => d.EndsWith(" " + v.Url, StringComparison.Ordinal)));

        Assert.Contains(s.Searches, x => x.Terms == "cheap flights" && x.Profile.Browser == "Google Chrome");
        Assert.Contains(s.Searches, x => x.Terms == "green tea" && x.Profile.Browser == "Firefox");
        Assert.Contains(s.Searches, x => x.Terms == "printer drivers" && x.Profile.Browser.StartsWith("Internet Explorer", StringComparison.Ordinal));

        Assert.True(s.Downloads.Single(d => d.TargetPath == OldPcDrive.KeptDownload).StillOnDisk);
        Assert.False(s.Downloads.Single(d => d.TargetPath == OldPcDrive.GoneDownload).StillOnDisk);
        Assert.Equal(["Flights", "News", "Teapot"], s.Bookmarks.Select(b => b.Title).Order(StringComparer.Ordinal));
        Assert.Contains(s.Tabs, t => t.Url == "https://mail.example/inbox" && t.State == TabState.Open);
        Assert.Contains(s.Tabs, t => t.Url == "https://shop.example/teapot" && t.Profile.Browser == "Firefox");
        Assert.Contains(s.Forms, f => f.Field == "email" && f.Value == "bob@example.com");
        Assert.Contains(s.Forms, f => f.Field == "searchbar-history" && f.Value == "green tea");
        Assert.DoesNotContain(s.Forms, f => f.Field.Contains("pass", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(s.Visits, v => v.Url == "https://intranet.example/home" && v.Profile.Family == BrowserFamily.WebCache);
        Assert.Contains(s.Notes, n => n.Contains("Restore points belong to the running PC", StringComparison.Ordinal));

        Assert.True(File.Exists(r.ReportPath));
        Assert.False(Directory.Exists(Path.Combine(r.CaseFolder, "work")));
        Assert.False(Directory.Exists(CaseFolder.WorkFolderFor(r.CaseFolder)));
        using var db = CaseDb.Open(Path.Combine(r.CaseFolder, "case.db"));
        var counts = db.CountByCategory();
        Assert.Equal(s.Visits.Count, counts["WebHistory.Visit"]);
        Assert.Equal(s.Forms.Count, counts["WebHistory.Form"]);
    }

    [Fact]
    public void No_secret_leaks_into_the_report_case_db_or_json()
    {
        var r = Run();
        foreach (var file in Directory.EnumerateFiles(r.CaseFolder, "*", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.False(Contains(bytes, Encoding.UTF8.GetBytes(OldPcDrive.Canary)) || Contains(bytes, Encoding.Unicode.GetBytes(OldPcDrive.Canary)),
                $"The planted secret appears in {Path.GetRelativePath(r.CaseFolder, file)}.");
        }
        // What the CLI prints with --json and writes to its log (summary, notes, warnings), and everything found.
        var json = JsonSerializer.Serialize(new { summary = HistoryJob.Summarize(r), r.Scan.Notes, r.Scan.Warnings, r.FolderWarnings,
            r.Scan.Visits, r.Scan.Searches, r.Scan.Downloads, r.Scan.Bookmarks, r.Scan.Tabs, r.Scan.Forms });
        Assert.DoesNotContain(OldPcDrive.Canary, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void History_run_does_not_change_the_old_drive()
    {
        var before = _drive.Fingerprint();
        Run();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var after = _drive.Fingerprint();
        Assert.Empty(after.Keys.Except(before.Keys));                            // nothing added (no -wal, -shm, journal, ESE logs)
        Assert.Empty(before.Keys.Except(after.Keys));
        Assert.All(before, kv => Assert.True(after[kv.Key] == kv.Value, $"{kv.Key} changed."));
    }

    /// <summary>Spy: every file the history job opens or lists goes through SourceFiles; the bait files never do.</summary>
    [Fact]
    public void Password_cookie_and_key_files_are_never_opened_and_card_tables_never_queried()
    {
        var access = new ConcurrentQueue<(string Kind, string Path)>();
        HistoryJobResult r;
        using (SourceFiles.Observe((kind, path) => access.Enqueue((kind, path))))
            r = Run();

        var reads = access.Where(a => a.Kind == "read").Select(a => Path.GetFullPath(a.Path)).ToList();
        Assert.Contains(reads, p => p.EndsWith(@"\Default\History", StringComparison.OrdinalIgnoreCase));      // the spy sees the reads...
        Assert.Contains(reads, p => p.EndsWith(@"\Default\Web Data", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(reads, p => p.EndsWith(@"\places.sqlite", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(reads, p => p.EndsWith(@"\WebCacheV01.dat", StringComparison.OrdinalIgnoreCase));
        foreach (var bait in OldPcDrive.BaitFiles.Select(b => Path.GetFullPath(_drive.At(b))))                 // ...but never these
            Assert.DoesNotContain(bait, reads, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(reads, p => Path.GetFileName(p) is "Login Data" or "Cookies" or "key4.db" or "logins.json");
        var root = Path.GetFullPath(_drive.Root);
        Assert.All(access, a => Assert.True(Path.GetFullPath(a.Path).StartsWith(root, StringComparison.OrdinalIgnoreCase), $"Read outside the drive: {a.Path}"));

        // Web Data is read with one statement on the autofill table, behind a guard that refuses every other table.
        Assert.Equal("SELECT name, value, count, date_created, date_last_used FROM autofill", ChromiumWebData.AutofillSql);
        Assert.NotEmpty(r.Scan.Forms);
    }

    // ---- helpers ----

    static bool Contains(byte[] hay, byte[] needle) => hay.AsSpan().IndexOf(needle) >= 0;

    /// <summary>Stable text summary: per profile and origin counts, first/last dates, top sites. No paths, times of the run or ids.</summary>
    static string Summary(HistoryJobResult r)
    {
        var s = r.Scan;
        var sb = new StringBuilder();
        string D(DateTimeOffset? t) => t is { } x ? x.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "-";
        foreach (var p in s.Profiles.OrderBy(p => p.Browser, StringComparer.Ordinal).ThenBy(p => p.Name, StringComparer.Ordinal))
        {
            var visits = s.Visits.Where(v => v.Profile == p).ToList();
            var cov = s.Coverage.Single(c => c.Profile == p);
            sb.AppendLine($"profile {p.Browser} / {p.Name} ({p.User}, {p.Family}): live visits {cov.Visits}, first {D(cov.Earliest)}, last {D(cov.Latest)}");
            foreach (var g in visits.GroupBy(v => v.Origin).OrderBy(g => g.Key))
                sb.AppendLine($"  {g.Key}: {g.Count()} visits, first {D(g.Min(v => v.When))}, last {D(g.Max(v => v.When))}");
            foreach (var g in visits.GroupBy(v => v.How).OrderBy(g => g.Key)) sb.AppendLine($"  how {g.Key}: {g.Count()}");
            sb.AppendLine($"  searches {s.Searches.Count(x => x.Profile == p)}, downloads {s.Downloads.Count(x => x.Profile == p)} " +
                          $"(on disk {s.Downloads.Count(x => x.Profile == p && x.StillOnDisk == true)}), bookmarks {s.Bookmarks.Count(x => x.Profile == p)}, " +
                          $"tabs {s.Tabs.Count(x => x.Profile == p)}, form entries {s.Forms.Count(x => x.Profile == p)}");
        }
        sb.AppendLine($"total: {s.Visits.Count} visits ({s.Visits.Count(v => v.Origin != Origin.Live)} recovered), {s.Searches.Count} searches, " +
                      $"{s.Downloads.Count} downloads, {s.Bookmarks.Count} bookmarks, {s.Tabs.Count} tabs, {s.Forms.Count} form entries");
        foreach (var site in s.Visits.GroupBy(v => Uri.TryCreate(v.Url, UriKind.Absolute, out var u) ? u.Host : v.Url)
                     .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(5))
            sb.AppendLine($"top site {site.Key}: {site.Count()}");
        sb.AppendLine($"notes {s.Notes.Count}, warnings {s.Warnings.Count}");
        return sb.ToString().Replace("\r\n", "\n");
    }
}
