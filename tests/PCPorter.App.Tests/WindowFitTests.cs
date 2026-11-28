using System.Windows;
using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class WindowFitTests
{
    const double W = 1200, H = 780, MinW = 760, MinH = 500;

    [Fact]
    public void Big_screen_keeps_the_designed_size_centred()
    {
        var p = WindowFit.Fit(new Rect(0, 0, 1920, 1040), W, H, MinW, MinH);
        Assert.Equal((360d, 130d, W, H), (p.Left, p.Top, p.Width, p.Height));
        Assert.Equal((MinW, MinH), (p.MinWidth, p.MinHeight));
    }

    [Fact]
    public void Laptop_1366x768_shrinks_above_the_taskbar()
    {
        var wa = new Rect(0, 0, 1366, 728);   // 40 px taskbar at the bottom
        var p = WindowFit.Fit(wa, W, H, MinW, MinH);
        Assert.Equal(W, p.Width);
        Assert.Equal(728 - 2 * WindowFit.Margin, p.Height);
        Assert.Equal(WindowFit.Margin, p.Top);
        Assert.True(p.Top + p.Height <= wa.Bottom);
    }

    [Fact]
    public void Full_hd_at_150_percent_shrinks_in_height()
    {
        var wa = new Rect(0, 0, 1280, 693.33);   // 1920x1040 work area in DIPs at 150%
        var p = WindowFit.Fit(wa, W, H, MinW, MinH);
        Assert.Equal(W, p.Width);
        Assert.Equal(693.33 - 2 * WindowFit.Margin, p.Height, 3);
        Assert.Equal((40d, WindowFit.Margin), (p.Left, p.Top));
    }

    [Fact]
    public void Narrow_scaled_screen_shrinks_in_width()
    {
        var wa = new Rect(0, 0, 1092.8, 582.4);   // 1366x768 at 125%, taskbar 48 px
        var p = WindowFit.Fit(wa, W, H, MinW, MinH);
        Assert.Equal(1092.8 - 2 * WindowFit.Margin, p.Width, 3);
        Assert.Equal(582.4 - 2 * WindowFit.Margin, p.Height, 3);
        Assert.Equal(WindowFit.Margin, p.Left, 3);
    }

    [Fact]
    public void Work_area_offset_by_a_left_or_top_taskbar_is_respected()
    {
        var p = WindowFit.Fit(new Rect(60, 0, 1306, 768), W, H, MinW, MinH);
        Assert.Equal(60 + (1306 - W) / 2, p.Left);
        Assert.True(p.Left >= 60);
    }

    [Fact]
    public void Tiny_screen_lowers_the_minimum_so_the_window_stays_on_screen()
    {
        var wa = new Rect(0, 0, 700, 450);
        var p = WindowFit.Fit(wa, W, H, MinW, MinH);
        Assert.Equal((700d, 450d), (p.MinWidth, p.MinHeight));
        Assert.Equal((700d, 450d), (p.Width, p.Height));
        Assert.Equal((0d, 0d), (p.Left, p.Top));
    }

    [Fact]
    public void Between_minimum_and_margin_the_minimum_wins()
    {
        var p = WindowFit.Fit(new Rect(0, 0, 780, 510), W, H, MinW, MinH);   // room after margins is below the minimum
        Assert.Equal((MinW, MinH), (p.Width, p.Height));
        Assert.Equal((10d, 5d), (p.Left, p.Top));
    }
}
