using System.ComponentModel;
using System.Windows;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Security;
using Serilog;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace PCPorter.App;

public partial class MainWindow : FluentWindow
{
    /// <summary>How long closing waits for a stopped job's clean-up before giving up.</summary>
    static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(30);

    bool _stopped;   // the jobs were stopped (or there were none): the next Close really closes

    public MainWindow()
    {
        InitializeComponent();
        Title = AppTitle.Title = TitleFor(AppFolders.IsElevated);
        SystemThemeWatcher.Watch(this);   // follow Windows light/dark mode and accent color
        WindowFit.Apply(this);            // shrink to small or scaled screens; centred in the area above the taskbar
        Loaded += (_, _) => Nav.Navigate(typeof(Views.HomePage));
    }

    /// <summary>The title says "administrator" only when PCPorter really runs as administrator.</summary>
    public static string TitleFor(bool elevated) => elevated ? "PCPorter  -  running as administrator" : "PCPorter";

    /// <summary>
    /// Closing while a job runs would end the process before the job removes its work folder (copied browser
    /// databases) or its temporary shadow copy. Ask, stop the job, wait for its clean-up, then close.
    /// </summary>
    protected override async void OnClosing(CancelEventArgs e)
    {
        if (_stopped || !RunningJobs.Instance.Any) { base.OnClosing(e); return; }
        e.Cancel = true;
        var answer = System.Windows.MessageBox.Show(this,
            "PCPorter is still working. Stop it and close?\n\nWhat was found so far is not saved.",
            "Stop and close?", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        IsEnabled = false;
        Title = AppTitle.Title = "PCPorter  -  stopping...";
        Log.Information("Closing: stopping the running job");
        if (!await RunningJobs.Instance.StopAllAsync(StopTimeout))
            Log.Warning("Closing: a job did not stop within {Seconds} s", StopTimeout.TotalSeconds);
        _stopped = true;
        Close();
    }
}
