using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// A page's status line that screen readers hear: setting the text raises LiveRegionChanged (LiveSetting alone is not
/// announced for TextBlock changes). <see cref="Progress"/> is for a stream of progress lines: always shown, but
/// announced at most once per <see cref="MinGap"/> and never when it holds a file path (Narrator would read it out
/// letter by letter, and it can name private files).
/// </summary>
public sealed partial class LiveStatus(TextBlock target, Func<DateTime>? clock = null)
{
    public static readonly TimeSpan MinGap = TimeSpan.FromSeconds(3);

    readonly Func<DateTime> _clock = clock ?? (() => DateTime.UtcNow);
    DateTime? _lastAnnounced;

    /// <summary>Shows and announces <paramref name="text"/> (a step, a result, "Stopping...").</summary>
    public void Set(string text)
    {
        target.Text = text;
        Raise();
        _lastAnnounced = _clock();
    }

    /// <summary>Shows <paramref name="text"/>; announces it only when <see cref="ShouldAnnounce"/> says so.</summary>
    public void Progress(string text)
    {
        target.Text = text;
        var now = _clock();
        if (!ShouldAnnounce(text, now, _lastAnnounced)) return;
        Raise();
        _lastAnnounced = now;
    }

    /// <summary>The throttle: no file paths, and not within <see cref="MinGap"/> of the last announcement.</summary>
    public static bool ShouldAnnounce(string text, DateTime now, DateTime? last) =>
        !HoldsPath(text) && (last is not { } l || now - l >= MinGap);

    /// <summary>A drive path (C:\...), a network or device path (\\server\...), or a file:// address.</summary>
    public static bool HoldsPath(string text)
    {
        try { return PathPattern().IsMatch(text); }
        catch (RegexMatchTimeoutException) { return true; }   // unsure: stay quiet
    }

    [GeneratedRegex(@"[A-Za-z]:[\\/]|\\\\|file:/", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PathPattern();

    void Raise() =>
        (UIElementAutomationPeer.FromElement(target) ?? UIElementAutomationPeer.CreatePeerForElement(target))
            ?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);

    /// <summary>
    /// Keyboard focus while a job runs and after it: Cancel while it runs (the focused Start button is disabled, which
    /// would drop focus to the window), then "Open the report" when shown, else Start.
    /// </summary>
    public static void FocusForJob(bool busy, UIElement cancel, UIElement openReport, UIElement start)
    {
        if (busy) { cancel.Focus(); return; }
        if (openReport.Visibility == Visibility.Visible && openReport.IsEnabled) openReport.Focus();
        else start.Focus();
    }
}
