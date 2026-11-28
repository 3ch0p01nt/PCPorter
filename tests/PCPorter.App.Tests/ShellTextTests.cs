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
