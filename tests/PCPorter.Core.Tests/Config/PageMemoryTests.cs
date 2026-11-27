using PCPorter.Core.Config;

namespace PCPorter.Core.Tests.Config;

public class PageMemoryTests : IDisposable
{
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-test").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    string SettingsFile => Path.Combine(_dir, "settings.json");

    static readonly LastRun Run = new(new DateTime(2026, 11, 27, 14, 5, 0), RunOutcome.Partial, "12 visits found.",
        @"D:\Cases\case-1\report.html", @"D:\Cases\case-1");

    [Fact] public void Page_memory_round_trips_and_keeps_other_settings()
    {
        var store = new SettingsStore(_dir);
        store.Save(new AppSettings { Theme = "Dark", RecentCases = ["x"] });
        var pages = new PageMemoryStore(store);

        pages.Update("history", m => m with
        {
            SaveFolder = @"C:\PCPorterCases\uitest", Source = PageMemory.OtherDrive, DriveRoot = @"E:\",
            Options = new() { ["allUsers"] = true, ["restorePoints"] = false }, LastRun = Run,
        });
        pages.Update("scan", m => m with { SaveFolder = @"F:\" });

        var h = new PageMemoryStore(new SettingsStore(_dir)).Get("history");
        Assert.Equal(@"C:\PCPorterCases\uitest", h.SaveFolder);
        Assert.Equal(PageMemory.OtherDrive, h.Source);
        Assert.Equal(@"E:\", h.DriveRoot);
        Assert.True(h.Options["allUsers"]);
        Assert.False(h.Options["restorePoints"]);
        Assert.Equal(Run, h.LastRun);
        Assert.Equal(@"F:\", pages.Get("scan").SaveFolder);
        var s = store.Load();
        Assert.Equal("Dark", s.Theme);
        Assert.Equal(["x"], s.RecentCases);
        Assert.Contains("\"Partial\"", File.ReadAllText(SettingsFile));   // outcome stored by name, not number
    }

    [Fact] public void Old_settings_file_without_pages_loads()
    {
        File.WriteAllText(SettingsFile, """{ "SchemaVersion": 1, "FirstRunCompleted": true, "Theme": "Light", "CheckForUpdates": false, "RecentCases": [] }""");
        var s = new SettingsStore(_dir).Load();
        Assert.True(s.FirstRunCompleted);
        Assert.Empty(s.Pages);
        Assert.False(File.Exists(SettingsFile + ".corrupt"));
        var m = new PageMemoryStore(new SettingsStore(_dir)).Get("history");
        Assert.Null(m.SaveFolder);
        Assert.Null(m.LastRun);
    }

    [Fact] public void Null_pages_in_the_file_still_works()
    {
        File.WriteAllText(SettingsFile, """{ "SchemaVersion": 1, "Pages": null }""");
        var pages = new PageMemoryStore(new SettingsStore(_dir));
        Assert.Null(pages.Get("scan").SaveFolder);
        pages.Update("scan", m => m with { SaveFolder = @"F:\" });
        Assert.Equal(@"F:\", pages.Get("scan").SaveFolder);
    }

    [Fact] public void Corrupt_file_falls_back_and_the_next_save_replaces_it()
    {
        File.WriteAllText(SettingsFile, "{ \"Pages\": { \"history\": ");
        var pages = new PageMemoryStore(new SettingsStore(_dir));
        Assert.Null(pages.Get("history").LastRun);
        Assert.True(File.Exists(SettingsFile + ".corrupt"));
        pages.Update("history", m => m with { SaveFolder = @"C:\PCPorterCases" });
        Assert.Equal(@"C:\PCPorterCases", pages.Get("history").SaveFolder);
    }

    [Fact] public void Missing_report_hides_the_last_run_and_forgets_it()
    {
        var pages = new PageMemoryStore(new SettingsStore(_dir));
        pages.Update("history", m => m with { SaveFolder = @"C:\PCPorterCases\uitest", LastRun = Run });

        Assert.Null(pages.RecallLastRun("history", _ => false));
        var after = pages.Get("history");
        Assert.Null(after.LastRun);
        Assert.Equal(@"C:\PCPorterCases\uitest", after.SaveFolder);   // inputs are kept
    }

    [Fact] public void Existing_report_shows_the_last_run()
    {
        var report = Path.Combine(_dir, "report.html");
        File.WriteAllText(report, "<html></html>");
        var pages = new PageMemoryStore(new SettingsStore(_dir));
        pages.Update("scan", m => m with { LastRun = Run with { ReportPath = report } });

        Assert.Equal(report, pages.RecallLastRun("scan")?.ReportPath);
        Assert.NotNull(pages.Get("scan").LastRun);
    }

    [Fact] public void Run_without_a_report_is_never_shown()
    {
        Assert.False(PageMemoryStore.ShouldShow(Run with { ReportPath = null }, _ => true));
        Assert.False(PageMemoryStore.ShouldShow(Run with { ReportPath = "" }, _ => true));
        Assert.True(PageMemoryStore.ShouldShow(Run, _ => true));
    }

    [Fact] public void Describe_uses_a_fixed_date_format()
    {
        Assert.Equal("Last check: 27 Nov 2026 14:05 - 12 visits found.", PageMemoryStore.Describe("Last check", Run));
    }

    [Fact] public void Write_errors_are_reported_not_thrown()
    {
        var blocker = Path.Combine(_dir, "file-not-folder");
        File.WriteAllText(blocker, "");
        var errors = new List<Exception>();
        var pages = new PageMemoryStore(new SettingsStore(Path.Combine(blocker, "sub")), errors.Add);

        pages.Update("history", m => m with { SaveFolder = "x" });   // the settings folder cannot be created
        Assert.Single(errors);
        Assert.Null(pages.Get("history").SaveFolder);
    }
}
