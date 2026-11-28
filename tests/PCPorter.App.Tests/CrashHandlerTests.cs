using PCPorter.App.Infrastructure;
using PCPorter.Core.Security;

namespace PCPorter.App.Tests;

[Collection("Console")]   // swaps the static dialog hook
public class CrashHandlerTests
{
    static List<string> Capture()
    {
        var shown = new List<string>();
        CrashHandler.ShowError = shown.Add;
        return shown;
    }

    [Fact]
    public void An_unobserved_task_is_logged_and_marked_observed_without_a_dialog()
    {
        var shown = Capture();
        var e = new UnobservedTaskExceptionEventArgs(new AggregateException(new InvalidOperationException("late")));
        CrashHandler.OnUnobserved(e);
        Assert.True(e.Observed);
        Assert.Empty(shown);
    }

    [Fact]
    public void A_fatal_error_says_PCPorter_has_to_close()
    {
        var shown = Capture();
        CrashHandler.OnFatal(new InvalidOperationException("boom"), System.Windows.Threading.Dispatcher.CurrentDispatcher);
        Assert.Single(shown);
        Assert.StartsWith("PCPorter has to close", shown[0]);
    }

    [Fact]
    public void A_fatal_error_without_a_ui_thread_shows_nothing_and_does_not_throw()
    {
        var shown = Capture();
        CrashHandler.OnFatal(null, null);
        Assert.Empty(shown);
    }

    [Fact]
    public void Start_failure_message_for_an_unsafe_admin_folder()
    {
        var m = Logging.StartFailure(new UnsafeAppFolderException("PCPorter could not make its working folder safe."));
        Assert.StartsWith("PCPorter can't start: PCPorter could not make", m);
        Assert.StartsWith("PCPorter can't start: its log folder", Logging.StartFailure(new IOException("disk")));
    }
}
