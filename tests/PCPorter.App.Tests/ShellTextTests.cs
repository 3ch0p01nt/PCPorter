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

    static SaveDrive Drive(string root, long freeGb = 100, bool usb = false, bool removable = false, bool windows = false, string? label = null) =>
        new(root, label, freeGb * 1024L * 1024 * 1024, usb, removable, windows);

    [Fact]
    public async Task Save_folder_shows_the_default_at_once_and_the_backup_drive_when_found()
    {
        var box = "";
        using var release = new SemaphoreSlim(0);
        var pending = WindowsDrives.SuggestSaveFolderAsync(() => box, s => box = s, () => { release.Wait(); return [Drive(@"F:\")]; });
        Assert.Equal(WindowsDrives.DefaultSaveFolder, box);     // before the (slow) drive lookup has answered
        release.Release();
        Assert.Single(await pending);
        Assert.Equal(@"F:\", box);
    }

    [Fact]
    public async Task Save_folder_typed_meanwhile_is_kept()
    {
        var box = "";
        using var release = new SemaphoreSlim(0);
        var pending = WindowsDrives.SuggestSaveFolderAsync(() => box, s => box = s, () => { release.Wait(); return [Drive(@"F:\")]; });
        box = @"D:\Mine";
        release.Release();
        await pending;
        Assert.Equal(@"D:\Mine", box);
    }

    [Fact]
    public async Task No_other_drive_keeps_the_default()
    {
        var box = "";
        Assert.Empty(await WindowsDrives.SuggestSaveFolderAsync(() => box, s => box = s, () => []));
        Assert.Equal(WindowsDrives.DefaultSaveFolder, box);
    }

    [Fact]
    public void A_usb_hard_drive_reported_as_fixed_is_suggested_first_and_the_pcs_own_drives_never()
    {
        var ranked = WindowsDrives.RankSaveDrives(
        [
            Drive(@"C:\", 400),                            // Windows runs from here: about to be reset
            Drive(@"D:\", 900),                            // a second internal disk
            Drive(@"E:\", 20, removable: true, usb: true), // a USB stick
            Drive(@"F:\", 800, usb: true, label: "Backup"),// a USB hard drive: Windows says "Fixed"
            Drive(@"G:\", 300, usb: true, windows: true),  // the old PC's drive in a USB adapter
        ], @"C:\");
        Assert.Equal([@"F:\", @"E:\", @"D:\"], ranked.Select(d => d.Root));
    }

    [Theory]
    [InlineData(@"C:\PCPorterCases", true)]
    [InlineData(@"c:\", true)]
    [InlineData(@"E:\Backup", false)]
    [InlineData(@"relative\path", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void The_warning_shows_only_for_a_folder_on_the_system_drive(string? folder, bool warn) =>
        Assert.Equal(warn, WindowsDrives.IsOnSystemDrive(folder, @"C:\"));

    [Fact]
    public void A_subst_letter_of_the_system_drive_still_warns()
    {
        string? Dos(string letter) => letter switch { "S:" => @"\??\C:\Users\bob\Saves", "T:" => @"\??\S:\deeper", "E:" => @"\Device\HarddiskVolume7", _ => null };
        Assert.True(WindowsDrives.IsOnSystemDrive(@"S:\Cases", @"C:\", Dos));
        Assert.True(WindowsDrives.IsOnSystemDrive(@"T:\Cases", @"C:\", Dos));       // subst of a subst
        Assert.False(WindowsDrives.IsOnSystemDrive(@"E:\Cases", @"C:\", Dos));
    }

    [Fact]
    public void The_warning_says_what_happens_and_what_to_do() =>
        Assert.Equal("Results saved on this PC are lost when it is reset: save to your backup drive.", WindowsDrives.SystemDriveWarning);

    [Fact]
    public void A_drive_in_the_list_shows_its_label_kind_and_free_space()
    {
        Assert.Equal(@"F:\ Backup (USB drive, 812 GB free)", Drive(@"F:\", 812, usb: true, label: "Backup").ToString());
        Assert.Equal(@"D:\ (drive, 4.5 GB free)", new SaveDrive(@"D:\", "", 4_831_838_208, false, false, false).ToString());
        Assert.Equal(@"E:\ (removable drive, 700 MB free)", new SaveDrive(@"E:\", null, 700L * 1024 * 1024, false, true, false).ToString());
    }

    [Fact]
    public void The_live_drive_finder_never_lists_the_system_drive()
    {
        var found = WindowsDrives.FindSaveDrives();
        Assert.DoesNotContain(found, d => string.Equals(d.Root, WindowsDrives.SystemRoot, StringComparison.OrdinalIgnoreCase));
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
