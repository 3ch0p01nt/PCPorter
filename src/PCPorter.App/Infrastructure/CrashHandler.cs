using System.Windows;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>Logs every unhandled error and shows a friendly message instead of a raw stack trace.</summary>
public static class CrashHandler
{
    public static void Install(Application app)
    {
        app.DispatcherUnhandledException += (_, e) => { Report(e.Exception); e.Handled = true; };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Report(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { Report(e.Exception); e.SetObserved(); };
    }

    static void Report(Exception? ex)
    {
        Log.Fatal(ex, "Unhandled exception");
        MessageBox.Show(
            "Something went wrong and PCPorter stopped this action.\n\n" +
            $"The details are saved in the log folder:\n{Logging.Folder}",
            "PCPorter", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
