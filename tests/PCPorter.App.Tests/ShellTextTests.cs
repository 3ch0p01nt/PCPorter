using PCPorter.App.Views;

namespace PCPorter.App.Tests;

public class ShellTextTests
{
    [Fact]
    public void Title_says_administrator_only_when_elevated()
    {
        Assert.Contains("administrator", MainWindow.TitleFor(true));
        Assert.DoesNotContain("administrator", MainWindow.TitleFor(false));
    }

    [Fact]
    public void Drive_hint_without_administrator_says_how_to_look_instead_of_nothing_found()
    {
        Assert.Equal("Start PCPorter as administrator to look inside other drives.", WindowsDrives.Hint([], elevated: false));
        Assert.StartsWith("No other Windows drive found.", WindowsDrives.Hint([], elevated: true));
    }

    [Fact]
    public async Task Save_folder_shows_the_default_at_once_and_the_backup_drive_when_found()
    {
        var box = "";
        using var release = new SemaphoreSlim(0);
        var pending = WindowsDrives.SuggestSaveFolderAsync(() => box, s => box = s, () => { release.Wait(); return @"F:\"; });
        Assert.Equal(WindowsDrives.DefaultSaveFolder, box);     // before the (slow) drive lookup has answered
        release.Release();
        await pending;
        Assert.Equal(@"F:\", box);
    }

    [Fact]
    public async Task Save_folder_typed_meanwhile_is_kept()
    {
        var box = "";
        using var release = new SemaphoreSlim(0);
        var pending = WindowsDrives.SuggestSaveFolderAsync(() => box, s => box = s, () => { release.Wait(); return @"F:\"; });
        box = @"D:\Mine";
        release.Release();
        await pending;
        Assert.Equal(@"D:\Mine", box);
    }

    [Fact]
    public void Drive_hint_never_points_at_a_help_page_that_does_not_exist()
    {
        foreach (var elevated in new[] { true, false })
        {
            Assert.DoesNotContain("Help", WindowsDrives.Hint([new(@"E:\", @"E:\", true)], elevated));
            Assert.DoesNotContain("Help", WindowsDrives.Hint([], elevated));
            Assert.Contains("BitLocker", WindowsDrives.Hint([new(@"E:\", @"E:\ (locked or not ready)", false)], elevated));
        }
    }
}
