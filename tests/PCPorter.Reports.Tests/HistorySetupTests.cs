using PCPorter.Core.Case;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

/// <summary>The non-UI half of the Web history page and the CLI: options, save-folder rules, the result sentence.</summary>
public sealed class HistorySetupTests : IDisposable
{
    readonly string _temp = Directory.CreateTempSubdirectory("pcporter-histsetup").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_temp, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void All_accounts_without_administrator_falls_back_to_your_own_account_with_a_note()
    {
        var o = HistorySetup.Options(new HistoryRequest(_temp, null, AllUsers: true, RestorePoints: true), elevated: false);
        Assert.False(o.AllUsers);
        Assert.True(o.RestorePoints);
        Assert.Contains(o.ExtraNotes!, n => n.Contains("not running as administrator"));
    }

    [Theory]
    [InlineData(true, false)]       // administrator: all accounts as asked
    [InlineData(false, true)]       // another PC's drive: every account anyway, no note needed
    public void All_accounts_is_kept_when_allowed(bool elevated, bool offline)
    {
        var o = HistorySetup.Options(new HistoryRequest(_temp, offline ? @"D:\" : null, AllUsers: true, RestorePoints: false), elevated);
        Assert.True(o.AllUsers);
        Assert.False(o.RestorePoints);
        Assert.Empty(o.ExtraNotes!);
    }

    [Fact]
    public void Save_folder_on_the_drive_being_checked_is_refused()
    {
        Assert.NotNull(HistorySetup.SaveFolderProblem(@"D:\Cases", @"D:\"));
        Assert.NotNull(HistorySetup.SaveFolderProblem(@"d:\", @"D:\"));
        var drive = Path.Combine(_temp, "olddrive") + "\\";
        Assert.NotNull(HistorySetup.SaveFolderProblem(Path.Combine(drive, "Cases"), drive));
        Assert.Null(HistorySetup.SaveFolderProblem(Path.Combine(_temp, "olddrive-cases"), drive));   // a sibling, not inside
        Assert.Null(HistorySetup.SaveFolderProblem(@"E:\Cases", @"D:\"));
        Assert.Null(HistorySetup.SaveFolderProblem(@"E:\Cases", null));
    }

    [Fact]
    public void Save_folder_rules_include_the_cloud_sync_check()
    {
        var synced = Path.Combine(_temp, "OneDrive - Contoso", "Cases");
        Assert.Contains("OneDrive", HistorySetup.SaveFolderProblem(synced, null));
    }

    [Fact]
    public void Run_refuses_the_drive_being_checked_before_writing_anything()
    {
        var drive = Directory.CreateDirectory(Path.Combine(_temp, "olddrive")).FullName + "\\";
        var outRoot = Path.Combine(drive, "Cases");
        Assert.Throws<CaseLocationRejectedException>(() => HistorySetup.Run(new HistoryRequest(outRoot, drive, false, false), elevated: false));
        Assert.False(Directory.Exists(outRoot));
    }

    [Fact]
    public void Describe_says_what_was_found_in_plain_words()
    {
        var s = new HistorySummary("r", "c", Profiles: 2, Visits: 1234, Searches: 5, Downloads: 1, Recovered: 7, Notes: 0, Warnings: 0,
            Bookmarks: 3, Tabs: 4, Forms: 6);
        Assert.Equal("2 browser profiles: 1,234 visits (7 recovered after deletion or from restore points), 5 searches, 1 download, " +
                     "3 bookmarks, 4 tabs, 6 form entries.", HistorySetup.Describe(s, System.Globalization.CultureInfo.GetCultureInfo("en-US")));
        var none = new HistorySummary("r", "c", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        Assert.Equal("No web browser history was found.", HistorySetup.Describe(none, System.Globalization.CultureInfo.GetCultureInfo("en-US")));
        var one = new HistorySummary("r", "c", 1, 1, 0, 0, 0, 0, 0, 0, 0, 0);
        Assert.Equal("1 browser profile: 1 visit, 0 searches, 0 downloads, 0 bookmarks, 0 tabs, 0 form entries.",
            HistorySetup.Describe(one, System.Globalization.CultureInfo.GetCultureInfo("en-US")));
    }
}
