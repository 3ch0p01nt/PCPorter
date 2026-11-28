using System.Windows;
using System.Windows.Threading;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// Logs every unhandled error. A UI error is reported and the app carries on; a task nobody awaited is only logged
/// (it runs on the finalizer thread, where a dialog must never be shown); an error that ends the process says
/// "PCPorter has to close", shown on the UI thread when that thread still answers.
/// </summary>
public static class CrashHandler
{
    /// <summary>Shows a message on the UI thread (tests pass a fake).</summary>
    public static Action<string> ShowError { get; set; } = message =>
        MessageBox.Show(message, "PCPorter", MessageBoxButton.OK, MessageBoxImage.Error);

    public static void Install(Application app)
    {
        app.DispatcherUnhandledException += (_, e) => { OnUiError(e.Exception); e.Handled = true; };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => OnFatal(e.ExceptionObject as Exception, app.Dispatcher);
        TaskScheduler.UnobservedTaskException += (_, e) => OnUnobserved(e);
    }

    public static void OnUiError(Exception ex)
    {
        Log.Error(ex, "Unhandled exception on the UI thread");
        ShowError("Something went wrong and PCPorter stopped this action.\n\n" +
                  $"The details are saved in the log folder:\n{Logging.Folder}");
    }

    /// <summary>Finalizer thread: log and mark observed, never a dialog.</summary>
    public static void OnUnobserved(UnobservedTaskExceptionEventArgs e)
    {
        Log.Error(e.Exception, "A background task failed and nobody was waiting for it");
        e.SetObserved();
    }

    /// <summary>The process is about to end. Tell the person once, on the UI thread if it answers within a few seconds.</summary>
    public static void OnFatal(Exception? ex, Dispatcher? ui)
    {
        Log.Fatal(ex, "Unhandled exception: PCPorter has to close");
        var message = "PCPorter has to close because of an unexpected error.\n\n" +
                      $"The details are saved in the log folder:\n{Logging.Folder}";
        try
        {
            if (ui is null || ui.HasShutdownStarted) return;
            if (ui.CheckAccess()) ShowError(message);
            else ui.Invoke(() => ShowError(message), DispatcherPriority.Send, CancellationToken.None, TimeSpan.FromSeconds(5));
        }
        catch (Exception dialogError) when (dialogError is InvalidOperationException or TimeoutException or OperationCanceledException)
        {
            Log.Warning(dialogError, "Could not show the closing message");
        }
        finally { Logging.Close(); }
    }
}
