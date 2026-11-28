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
using PCPorter.App.Infrastructure;
using PCPorter.Collectors;
using PCPorter.Core.Case;
using PCPorter.Core.Config;
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
    bool _seen;                                     // the page is cached for the session: Loaded fires on every visit

    const string MemoryKey = "scan";
    readonly PageMemory _memory = Remembered.Pages.Get(MemoryKey);

    public ScanPage()
    {
        InitializeComponent();
        Cards.ItemsSource = _cards;
        _ = WindowsDrives.AttachSaveFolderAsync(OutFolder, SaveDrives, SaveDrivesRow, SystemDriveWarning, _memory.SaveFolder);
        _timer.Tick += (_, _) => Elapsed.Text = $"Elapsed {DateTime.Now - _startedAt:mm\\:ss}";
        ShowLastRun();
        Loaded += async (_, _) =>
        {
            if (_seen) return;
            _seen = true;
            await RefreshDrives();
            if (_memory.Source == PageMemory.OtherDrive && _cts is null
                && Drives.ItemsSource is List<DriveChoice> found && found.FirstOrDefault(c => c.Usable && c.Root == _memory.DriveRoot) is { } drive)
            { Drives.SelectedItem = drive; OtherDrive.IsChecked = true; }
        };
    }

    /// <summary>The last finished check, while its report still exists (otherwise it is forgotten).</summary>
    void ShowLastRun()
    {
        if (Remembered.LastRunOf(MemoryKey) is not { } last) return;
        _report = last.ReportPath; _case = last.CaseFolder;
        Announce(PageMemoryStore.Describe("Last check", last));
        OpenReport.Visibility = Visibility.Visible;
        OpenFolder.Visibility = CaseLinks.IsCaseFolder(_case) ? Visibility.Visible : Visibility.Collapsed;
    }

    void RememberRun(RunOutcome outcome, string summary) =>
        Remembered.Pages.Update(MemoryKey, m => m with { LastRun = new LastRun(DateTime.Now, outcome, summary, _report, _case) });

    /// <summary>Looks for other Windows drives off the UI thread (a sleeping USB disk can take seconds to answer).</summary>
    async Task RefreshDrives()
    {
        DriveHint.Text = "Looking for drives...";
        var candidates = await Task.Run(WindowsDrives.Find);
        Drives.ItemsSource = candidates;
        Drives.SelectedItem = candidates.FirstOrDefault(c => c.Usable);
        DriveHint.Text = WindowsDrives.Hint(candidates, _elevated);
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
        // Same check the scan job makes (by volume, so subst letters and mount points count as the drive being checked);
        // asked here too so the person gets the answer before anything starts.
        var check = CaseLocation.Check(outRoot, offline);
        if (!check.IsAllowed) { Show("Pick another folder", check.Reason!, InfoBarSeverity.Warning); return; }

        Remembered.Pages.Update(MemoryKey, m => m with
        { SaveFolder = outRoot, Source = offline is null ? PageMemory.ThisPc : PageMemory.OtherDrive, DriveRoot = offline });
        _report = _case = null;
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
            var cts = _cts;
            var r = await RunningJobs.Instance.Track(cts, Task.Run(() => ScanSetup.Run(outRoot, new ScanJobOptions(offline, false, _elevated), progress, cts.Token)));
            _report = r.ReportPath; _case = r.CaseFolder;
            foreach (var run in r.Run.Runs)
                (_cards.FirstOrDefault(c => c.Title == run.Collector) ?? AddCard(run.Collector)).State = Describe(run.Status, run.Items);

            var f = ScanSetup.CountFindings(r);
            var folderWarnings = FolderWarnings.Of(r);
            if (r.Run.Cancelled)
            {
                Announce("Scan stopped.");
                Show("Stopped", FolderWarnings.Append("The scan was stopped before the end. The report shows what was checked so far. Nothing on the PC was changed.", folderWarnings), InfoBarSeverity.Warning);
                RememberRun(RunOutcome.Stopped, "Stopped before the end; the report shows what was checked so far.");
            }
            else
            {
                var finished = f.WorthALook == 0 ? "Scan finished. Nothing stood out."
                    : $"Scan finished. {f.WorthALook} {(f.WorthALook == 1 ? "thing is" : "things are")} worth a look.";
                var gaps = r.Outcome is not ScanOutcome.Ok;
                var detail = r.CheckedWithLimits
                    ? "Checked from the drive. Antivirus state and hardware health can only be read on a running PC."
                    : gaps ? "Some parts could not be checked; the report says which and why." : "All parts were checked.";
                Announce(finished);
                Banner.IsOpen = f.WorthALook > 0;
                Show("Done", FolderWarnings.Append(detail, folderWarnings),
                    gaps || folderWarnings.Count > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success);
                RememberRun(gaps ? RunOutcome.Partial : RunOutcome.Ok, $"{finished} {detail}");
            }
            OpenReport.Visibility = CaseLinks.IsReport(_report) ? Visibility.Visible : Visibility.Collapsed;
            OpenFolder.Visibility = CaseLinks.IsCaseFolder(_case) ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (OperationCanceledException)
        {
            Announce("Scan stopped."); Show("Stopped", "Nothing was changed on the PC.", InfoBarSeverity.Warning);
            RememberRun(RunOutcome.Stopped, "Stopped before the report was written.");
        }
        catch (Exception ex)
        {
            var err = JobErrors.Describe(ex, "the results", Infrastructure.Logging.Folder);
            if (err.Kind == JobErrorKind.CantStart) Show(err.Title, err.Message, InfoBarSeverity.Warning);
            else
            {
                Log.Error(ex, "scan failed");
                Show(err.Title, err.Message, InfoBarSeverity.Error);
                RememberRun(RunOutcome.Failed, $"{err.Title}. {err.Message}");
            }
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
    void OpenReport_Click(object sender, RoutedEventArgs e) => CaseLinks.OpenReport(_report);
    void OpenFolder_Click(object sender, RoutedEventArgs e) => CaseLinks.OpenCaseFolder(_case);

    void Show(string title, string message, InfoBarSeverity severity)
    {
        Result.Title = title; Result.Message = message; Result.Severity = severity; Result.IsOpen = true;
    }
}
