using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using PCPorter.Collectors;
using PCPorter.Core.Case;
using PCPorter.Core.Security;
using PCPorter.Reports;
using Serilog;
using Wpf.Ui.Controls;

namespace PCPorter.App.Views;

public partial class ScanPage : Page
{
    public sealed class Card(string title) : INotifyPropertyChanged
    {
        string _state = "Waiting";
        public string Title { get; } = title;
        public string State { get => _state; set { _state = value; PropertyChanged?.Invoke(this, new(nameof(State))); } }
        public event PropertyChangedEventHandler? PropertyChanged;
    }

    readonly ObservableCollection<Card> _cards = [];
    readonly bool _elevated = AppFolders.IsElevated;
    readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    CancellationTokenSource? _cts;
    DateTime _startedAt;
    string? _report, _case;

    public ScanPage()
    {
        InitializeComponent();
        Cards.ItemsSource = _cards;
        OutFolder.Text = WindowsDrives.SuggestedSaveFolder();
        _timer.Tick += (_, _) => Elapsed.Text = $"Elapsed {DateTime.Now - _startedAt:mm\\:ss}";
        Loaded += async (_, _) => await RefreshDrives();
    }

    /// <summary>Looks for other Windows drives off the UI thread (a sleeping USB disk can take seconds to answer).</summary>
    async Task RefreshDrives()
    {
        DriveHint.Text = "Looking for drives...";
        var candidates = await Task.Run(WindowsDrives.Find);
        Drives.ItemsSource = candidates;
        Drives.SelectedItem = candidates.FirstOrDefault(c => c.Usable);
        DriveHint.Text = WindowsDrives.Hint(candidates);
    }

    async void RefreshDrives_Click(object sender, RoutedEventArgs e) => await RefreshDrives();

    void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Where should the results be saved?" };
        if (dlg.ShowDialog() == true) OutFolder.Text = dlg.FolderName;
    }

    async void Start_Click(object sender, RoutedEventArgs e)
    {
        var choice = OtherDrive.IsChecked == true ? Drives.SelectedItem as DriveChoice : null;
        if (OtherDrive.IsChecked == true && choice is not { Usable: true })
        { Show("Pick a drive", "Connect (and unlock) the old PC's drive, then press Refresh.", InfoBarSeverity.Warning); return; }
        var offline = choice?.Root;
        if (offline is null && !_elevated) { Show("Administrator rights needed", "Close PCPorter and start it again as administrator to check this PC.", InfoBarSeverity.Warning); return; }
        var outRoot = OutFolder.Text.Trim();
        var check = CaseLocation.Check(outRoot);
        if (!check.IsAllowed) { Show("Pick another folder", check.Reason!, InfoBarSeverity.Warning); return; }
        if (offline is not null && string.Equals(Path.GetPathRoot(Path.GetFullPath(outRoot)), offline, StringComparison.OrdinalIgnoreCase))
        { Show("Pick another folder", "Save the results somewhere other than the drive being checked, so nothing is written to it.", InfoBarSeverity.Warning); return; }

        _cards.Clear();
        Result.IsOpen = Banner.IsOpen = false;
        OpenReport.Visibility = OpenFolder.Visibility = Visibility.Collapsed;
        SetBusy(true);
        _cts = new CancellationTokenSource();
        _startedAt = DateTime.Now; _timer.Start();
        var progress = new Progress<ScanProgress>(p =>
        {
            var card = _cards.FirstOrDefault(c => c.Title == p.Collector) ?? AddCard(p.Collector);
            if (p.Status is null)
            {
                card.State = "Checking...";
                Announce($"Step {p.Step} of {p.Total}: {p.Collector}");
            }
            else card.State = Describe(p.Status.Value, p.Items);
        });
        try
        {
            var r = await Task.Run(() => ScanSetup.Run(outRoot, new ScanJobOptions(offline, false, _elevated), progress, _cts.Token));
            _report = r.ReportPath; _case = r.CaseFolder;
            foreach (var run in r.Run.Runs)
                (_cards.FirstOrDefault(c => c.Title == run.Collector) ?? AddCard(run.Collector)).State = Describe(run.Status, run.Items);

            var f = ScanSetup.CountFindings(r);
            if (r.Run.Cancelled)
            {
                Announce("Scan stopped.");
                Show("Stopped", "The scan was stopped before the end. The report shows what was checked so far. Nothing on the PC was changed.", InfoBarSeverity.Warning);
            }
            else
            {
                Announce(f.WorthALook == 0 ? "Scan finished. Nothing stood out."
                    : $"Scan finished. {f.WorthALook} {(f.WorthALook == 1 ? "thing is" : "things are")} worth a look.");
                Banner.IsOpen = f.WorthALook > 0;
                Show("Done", r.Run.AnyFailed || r.Run.AnyPartial ? "Some parts could not be checked; the report says which and why." : "All parts were checked.",
                    r.Run.AnyFailed || r.Run.AnyPartial ? InfoBarSeverity.Warning : InfoBarSeverity.Success);
            }
            OpenReport.Visibility = _report is null ? Visibility.Collapsed : Visibility.Visible;
            OpenFolder.Visibility = Visibility.Visible;
        }
        catch (OperationCanceledException) { Announce("Scan stopped."); Show("Stopped", "Nothing was changed on the PC.", InfoBarSeverity.Warning); }
        catch (Exception ex) when (ex is CaseLocationRejectedException or InvalidDataException or InvalidOperationException) { Show("Can't start", Redactor.Redact(ex.Message), InfoBarSeverity.Warning); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warning(ex, "scan failed");
            Show("Couldn't save the results", Redactor.Redact(ex.Message), InfoBarSeverity.Error);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "scan crashed");
            Show("Something went wrong", $"The scan stopped unexpectedly. Details are in the log folder: {Infrastructure.Logging.Folder}", InfoBarSeverity.Error);
        }
        finally { _timer.Stop(); SetBusy(false); _cts?.Dispose(); _cts = null; }
    }

    static string Describe(CollectorStatus s, int items) => s switch
    {
        CollectorStatus.Ok => $"Done - {items} found",
        CollectorStatus.Partial => $"Partly done - {items} found",
        CollectorStatus.SkippedOffline => "Not available for another PC's drive",
        CollectorStatus.Cancelled => "Stopped",
        CollectorStatus.TimedOut => "Took too long and was skipped",
        _ => "Couldn't finish this part - details are in the report",
    };

    void SetBusy(bool busy)
    {
        Inputs.IsEnabled = !busy;
        StartButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
    }

    /// <summary>Updates the status line and tells Narrator (LiveSetting alone is not announced for TextBlock changes).</summary>
    void Announce(string text)
    {
        Step.Text = text;
        (UIElementAutomationPeer.FromElement(Step) ?? UIElementAutomationPeer.CreatePeerForElement(Step))
            ?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    Card AddCard(string title) { var c = new Card(title); _cards.Add(c); return c; }

    void Cancel_Click(object sender, RoutedEventArgs e) { _cts?.Cancel(); CancelButton.IsEnabled = false; Announce("Stopping after the current step..."); }
    void OpenReport_Click(object sender, RoutedEventArgs e) { if (_report is not null) Process.Start(new ProcessStartInfo(_report) { UseShellExecute = true }); }
    void OpenFolder_Click(object sender, RoutedEventArgs e) { if (_case is not null) Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), _case); }

    void Show(string title, string message, InfoBarSeverity severity)
    {
        Result.Title = title; Result.Message = message; Result.Severity = severity; Result.IsOpen = true;
    }
}
