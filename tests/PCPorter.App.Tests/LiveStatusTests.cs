using System.Windows.Controls;
using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class LiveStatusTests
{
    static readonly DateTime T0 = new(2026, 11, 27, 10, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(@"C:\Users\sam\Pictures\holiday.jpg", true)]
    [InlineData(@"Reading d:/Users/sam/AppData", true)]
    [InlineData(@"\\server\share\x", true)]
    [InlineData("file:///C:/x.png", true)]
    [InlineData("Sam: Chrome cache", false)]
    [InlineData("Finding similar pictures", false)]
    [InlineData("Step 3 of 12: Startup apps", false)]
    public void File_paths_are_recognised(string text, bool path) => Assert.Equal(path, LiveStatus.HoldsPath(text));

    [Fact]
    public void Progress_is_announced_at_most_every_few_seconds_and_never_with_a_path()
    {
        Assert.True(LiveStatus.ShouldAnnounce("Sam: Chrome cache", T0, null));
        Assert.False(LiveStatus.ShouldAnnounce("Sam: Edge cache", T0 + TimeSpan.FromSeconds(1), T0));
        Assert.True(LiveStatus.ShouldAnnounce("Sam: Edge cache", T0 + LiveStatus.MinGap, T0));
        Assert.False(LiveStatus.ShouldAnnounce(@"Reading C:\Users\sam\x.jpg", T0 + TimeSpan.FromMinutes(1), T0));
    }

    [Fact]
    public void Every_line_is_shown_even_when_it_is_not_read_out()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var now = T0;
                var block = new TextBlock();
                var status = new LiveStatus(block, () => now);
                status.Set("Building the gallery...");
                status.Progress(@"C:\Users\sam\x.jpg");
                Assert.Equal(@"C:\Users\sam\x.jpg", block.Text);
                now += TimeSpan.FromSeconds(1);
                status.Progress("Sam: Chrome cache");
                Assert.Equal("Sam: Chrome cache", block.Text);
            }
            catch (Exception e) { failure = e; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw new Xunit.Sdk.XunitException(failure.ToString());
    }
}
