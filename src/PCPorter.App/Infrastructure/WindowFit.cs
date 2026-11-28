using System.Windows;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// Sizes the main window to the screen's work area (the screen minus the taskbar). Its designed size does not fit a
/// 1366x768 laptop or a 1920x1080 screen at 150% scaling, where the bottom (and the Start button of a page) would
/// sit under the taskbar.
/// </summary>
public static class WindowFit
{
    /// <summary>Space kept free around the window when it has to shrink.</summary>
    public const double Margin = 16;

    public readonly record struct Placement(double Left, double Top, double Width, double Height, double MinWidth, double MinHeight);

    /// <summary>
    /// The wanted size, shrunk to the work area less <see cref="Margin"/> on each side, centred in the work area.
    /// The minimum size is lowered too when the screen is smaller still, so the window can never be forced off screen.
    /// </summary>
    public static Placement Fit(Rect workArea, double width, double height, double minWidth, double minHeight)
    {
        var roomW = Math.Max(0, workArea.Width - 2 * Margin);
        var roomH = Math.Max(0, workArea.Height - 2 * Margin);
        var minW = Math.Min(minWidth, workArea.Width);
        var minH = Math.Min(minHeight, workArea.Height);
        var w = Math.Max(Math.Min(width, roomW), minW);
        var h = Math.Max(Math.Min(height, roomH), minH);
        return new(workArea.Left + (workArea.Width - w) / 2, workArea.Top + (workArea.Height - h) / 2, w, h, minW, minH);
    }

    /// <summary>Applies <see cref="Fit"/> to a window that is about to be shown, using its XAML size as the wish.</summary>
    public static void Apply(Window window)
    {
        var p = Fit(SystemParameters.WorkArea, window.Width, window.Height, window.MinWidth, window.MinHeight);
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.MinWidth = p.MinWidth;
        window.MinHeight = p.MinHeight;
        window.Width = p.Width;
        window.Height = p.Height;
        window.Left = p.Left;
        window.Top = p.Top;
    }
}
