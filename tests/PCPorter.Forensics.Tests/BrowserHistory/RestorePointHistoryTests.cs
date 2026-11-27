using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;
using static PCPorter.TestKit.ChromiumFixture;
using AdminFactAttribute = PCPorter.Forensics.Tests.SearchIndex.AdminFactAttribute;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class RestorePointHistoryTests
{
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    const string ChromeRel = @"Users\bob\AppData\Local\Google\Chrome\User Data\Default";
    const string FoxRel = @"Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release";

    static void Chrome(string folder, params (string Url, DateTimeOffset When)[] visits)
    {
        using var f = new ChromiumFixture(folder);
        foreach (var (url, when) in visits) f.Visit(f.Url(url, "T", when), when, ChainStart | ChainEnd | 1);
    }

    static void Fox(string folder, params (string Url, DateTimeOffset When)[] visits)
    {
        using var f = new FirefoxFixture(folder);
        foreach (var (url, when) in visits) f.Visit(f.Place(url, "F"), when, 1);
    }

    /// <summary>A restore point whose copy of the drive is a temp folder (the real ones are shadow copy devices).</summary>
    static RestorePointRoot Root(string liveRoot, string copyRoot, DateTimeOffset created) =>
        new(copyRoot, created, p => p.StartsWith(liveRoot + @"\", StringComparison.OrdinalIgnoreCase) ? copyRoot + p[liveRoot.Length..] : null);

    [Fact]
    public void Keeps_only_visits_missing_from_the_live_history_and_labels_the_restore_point()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var live = Path.Combine(dir, "live");
            var chrome = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", Path.Combine(live, ChromeRel));
            var fox = new BrowserProfile("bob", "Firefox", BrowserFamily.Firefox, "default-release", Path.Combine(live, FoxRel));
            Chrome(chrome.Folder, ("https://now.example/", T0), ("https://both.example/", T0.AddMinutes(1)));
            Fox(fox.Folder, ("https://fox-now.example/", T0));
            var work = Path.Combine(dir, "work");
            Directory.CreateDirectory(work);
            var known = ChromiumHistoryReader.Read(chrome, work).Visits.Concat(FirefoxHistoryReader.Read(fox, work).Visits).ToList();

            // October: an older Chrome history (one visit still live, one gone) and no Firefox profile yet.
            var rp1 = Path.Combine(dir, "rp1");
            Chrome(Path.Combine(rp1, ChromeRel), ("https://both.example/", T0.AddMinutes(1)), ("https://old.example/", T0.AddDays(-40)));
            // November: the same old visit again (reported once), plus an old Firefox visit.
            var rp2 = Path.Combine(dir, "rp2");
            Chrome(Path.Combine(rp2, ChromeRel), ("https://old.example/", T0.AddDays(-40)));
            Fox(Path.Combine(rp2, FoxRel), ("https://fox-old.example/", T0.AddDays(-20)), ("https://fox-now.example/", T0));

            var r = RestorePointHistory.Read([chrome, fox], known,
                [Root(live, rp1, new(2025, 10, 5, 3, 0, 0, TimeSpan.Zero)), Root(live, rp2, new(2025, 11, 9, 3, 0, 0, TimeSpan.Zero))], work);

            Assert.Equal(
            [
                new Visit(chrome, "https://old.example/", "T", T0.AddDays(-40), VisitHow.Typed, 0, Origin.RestorePoint, "restore point 2025-10-05"),
                new Visit(fox, "https://fox-old.example/", "F", T0.AddDays(-20), VisitHow.Link, 0, Origin.RestorePoint, "restore point 2025-11-09"),
            ], r.Visits);
            Assert.Empty(r.Warnings);
            Assert.Contains(r.Notes, n => n.Contains("2 older visits") && n.Contains("2 restore points"));
            Assert.Empty(Directory.GetDirectories(work));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void A_damaged_copy_is_a_warning_and_paths_outside_the_restore_point_are_never_read()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var live = Path.Combine(dir, "live");
            var chrome = new BrowserProfile("bob", "Google Chrome", BrowserFamily.Chromium, "Default", Path.Combine(live, ChromeRel));
            Chrome(chrome.Folder, ("https://now.example/", T0));
            var work = Path.Combine(dir, "work");
            Directory.CreateDirectory(work);

            var damaged = Path.Combine(dir, "rp1");
            BrowserFixtures.Touch(damaged, Path.Combine(ChromeRel, "History"), new string('x', 9000));
            // A restore point whose mapping leads outside its own root (to another folder with a readable History).
            var elsewhere = Path.Combine(dir, "elsewhere");
            Chrome(Path.Combine(elsewhere, ChromeRel), ("https://leak.example/", T0.AddDays(-3)));
            var escaping = new RestorePointRoot(Path.Combine(dir, "rp2"), new(2025, 11, 9, 0, 0, 0, TimeSpan.Zero),
                p => p.Replace(live, elsewhere, StringComparison.OrdinalIgnoreCase));
            Directory.CreateDirectory(escaping.Root);

            var r = RestorePointHistory.Read([chrome], [], [Root(live, damaged, new(2025, 10, 5, 0, 0, 0, TimeSpan.Zero)), escaping], work);

            Assert.Empty(r.Visits);
            Assert.Equal(2, r.Warnings.Count);
            Assert.Contains(r.Warnings, w => w.Contains("2025-10-05") && w.Contains("Google Chrome"));
            Assert.Contains(r.Warnings, w => w.Contains("2025-11-09") && w.Contains("outside"));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [AdminFact, Trait("Category", "Admin")]
    public void Lists_the_existing_restore_points_without_failing()
    {
        var roots = RestorePointHistory.ShadowCopies();
        Assert.All(roots, r =>
        {
            Assert.StartsWith(@"\\?\GLOBALROOT\Device\", r.Root, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith(r.Root.TrimEnd('\\'), r.Map(@"C:\Users")!, StringComparison.OrdinalIgnoreCase);
            Assert.Null(r.Map(@"D:\Data"));
        });
    }
}
