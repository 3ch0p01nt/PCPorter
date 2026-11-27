using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using Microsoft.Win32;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Case;
using PCPorter.Core.Config;
using PCPorter.Core.Security;
using PCPorter.Reports;
using Serilog;
using Wpf.Ui.Controls;

namespace PCPorter.App.Views;

/// <summary>
/// Web history report for this PC or another PC's drive. The rules (save folder, options, wording) live in
/// <see cref="HistorySetup"/> so the CLI and the tests share them; this page only gathers choices and shows progress.
/// </summary>
public partial class HistoryPage : Page
{
    readonly bool _elevated = AppFolders.IsElevated;
    CancellationTokenSource? _cts;
    string? _report, _case;
    bool? _allUsersOnThisPc, _restoreOnThisPc;     // the choices to give back when switching from another PC's drive
    bool _seen;                                     // the page is cached for the session: Loaded fires on every visit

    const string MemoryKey = "history";
    readonly PageMemory _memory = Remembered.Pages.Get(MemoryKey);

    public HistoryPage()
    {
        InitializeComponent();
        OutFolder.Text = string.IsNullOrWhiteSpace(_memory.SaveFolder) ? WindowsDrives.SuggestedSaveFolder() : _memory.SaveFolder;
        Remembered.RestoreOptions(_memory, ("allUsers", AllUsers), ("restorePoints", RestorePoints));
        ThisPc.Checked += (_, _) => UpdateOptions();
        OtherDrive.Checked += (_, _) => UpdateOptions();
        UpdateOptions();
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

    /// <summary>The last finished report, while its file still exists (otherwise it is forgotten).</summary>
    void ShowLastRun()
    {
        if (Remembered.Pages.RecallLastRun(MemoryKey) is not { } last) return;
        _report = last.ReportPath; _case = last.CaseFolder;
        Announce(PageMemoryStore.Describe("Last report", last));
        OpenReport.Visibility = Visibility.Visible;
        OpenFolder.Visibility = _case is not null && Directory.Exists(_case) ? Visibility.Visible : Visibility.Collapsed;
    }

    void RememberRun(RunOutcome outcome, string summary) =>
        Remembered.Pages.Update(MemoryKey, m => m with { LastRun = new LastRun(DateTime.Now, outcome, summary, _report, _case) });

    bool Offline => OtherDrive.IsChecked == true;

    /// <summary>
    /// This PC: other accounts and restore points need administrator. Another PC's drive: every account is always read
    /// and restore points (which belong to the running PC) are never searched.
    /// </summary>
    void UpdateOptions()
    {
        if (Offline)
        {
            _allUsersOnThisPc ??= AllUsers.IsChecked;
            _restoreOnThisPc ??= RestorePoints.IsChecked;
            AllUsers.IsChecked = true;
            RestorePoints.IsChecked = false;
            AllUsers.IsEnabled = RestorePoints.IsEnabled = false;
            AdminHint.Text = "Another PC's drive always shows every account on it. Restore points belong to this PC, so they are not searched.";
        }
        else
        {
            if (_allUsersOnThisPc is { } a) AllUsers.IsChecked = a;
            if (_restoreOnThisPc is { } r) RestorePoints.IsChecked = r;
            _allUsersOnThisPc = _restoreOnThisPc = null;
            if (!_elevated) AllUsers.IsChecked = RestorePoints.IsChecked = false;
            AllUsers.IsEnabled = RestorePoints.IsEnabled = _elevated;
            AdminHint.Text = _elevated ? "" : "The other accounts and restore points need PCPorter to run as administrator.";
        }
        AllUsers.ToolTip = AllUsers.IsEnabled ? null : AdminHint.Text;
        RestorePoints.ToolTip = RestorePoints.IsEnabled ? null : AdminHint.Text;
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
        var dlg = new OpenFolderDialog { Title = "Where should the report be saved?", InitialDirectory = Directory.Exists(OutFolder.Text) ? OutFolder.Text : null };
        if (dlg.ShowDialog() == true) OutFolder.Text = dlg.FolderName;
    }

    void Images_Click(object sender, RoutedEventArgs e) =>
        (Application.Current.MainWindow as MainWindow)?.Nav.Navigate(typeof(ThumbsPage));

    async void Start_Click(object sender, RoutedEventArgs e)
    {
        var choice = Offline ? Drives.SelectedItem as DriveChoice : null;
        if (Offline && choice is not { Usable: true })
        { Show("Pick a drive", "Connect (and unlock) the old PC's drive, then press Refresh.", InfoBarSeverity.Warning); return; }
        var outRoot = OutFolder.Text.Trim();
        if (outRoot.Length == 0) { Show("Pick a folder", "Choose where to save the report, ideally on your backup drive.", InfoBarSeverity.Warning); return; }
        if (HistorySetup.SaveFolderProblem(outRoot, choice?.Root) is { } problem) { Show("Pick another folder", problem, InfoBarSeverity.Warning); return; }

        // Not administrator on this PC: restore points stay "asked for" so the report says why they were not searched.
        var request = new HistoryRequest(outRoot, choice?.Root, AllUsers.IsChecked == true, Offline ? false : RestorePoints.IsChecked == true || !_elevated);
        var userChoice = !Offline && _elevated;   // otherwise both boxes are forced: keep what was remembered for this PC
        Remembered.Pages.Update(MemoryKey, m => m with
        {
            SaveFolder = outRoot, Source = Offline ? PageMemory.OtherDrive : PageMemory.ThisPc, DriveRoot = choice?.Root,
            Options = Remembered.Options(m, ("allUsers", AllUsers, userChoice), ("restorePoints", RestorePoints, userChoice)),
        });
        _report = _case = null;
        Result.IsOpen = false;
        OpenReport.Visibility = OpenFolder.Visibility = Visibility.Collapsed;
        SetBusy(true);
        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(m => Announce(Redactor.Redact(m)));   // the job runs on a worker; this posts back to the UI thread
        Announce("Building the web history report...");
        try
        {
            var r = await Task.Run(() => HistorySetup.Run(request, _elevated, progress, ct: _cts.Token));
            _report = r.ReportPath; _case = r.CaseFolder;
            var s = HistoryJob.Summarize(r);
            var found = HistorySetup.Describe(s);
            var message = found + (s.Warnings > 0 ? $" {s.Warnings} part{(s.Warnings == 1 ? "" : "s")} could not be read; the report's processing notes say which." : "");
            Show(s.Warnings > 0 ? "Report ready, with gaps" : "Report ready", message,
                s.Warnings > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success);
            Announce("Report ready. " + found);
            OpenReport.Visibility = OpenFolder.Visibility = Visibility.Visible;
            RememberRun(s.Warnings > 0 ? RunOutcome.Partial : RunOutcome.Ok, message);
        }
        catch (OperationCanceledException)
        {
            Announce("Stopped.");
            Show("Stopped", "Nothing was changed on the PC. A partly written case folder may remain.", InfoBarSeverity.Warning);
            RememberRun(RunOutcome.Stopped, "Stopped before the report was written.");
        }
        catch (Exception ex) when (ex is CaseLocationRejectedException or InvalidDataException or InvalidOperationException)
        {
            Show("Can't start", Redactor.Redact(ex.Message), InfoBarSeverity.Warning);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warning(ex, "history report could not be written");
            Show("Couldn't save the report", Redactor.Redact(ex.Message), InfoBarSeverity.Error);
            RememberRun(RunOutcome.Failed, "The report could not be saved.");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "history report crashed");
            Show("Something went wrong", $"The report stopped unexpectedly. Details are in the log folder: {Infrastructure.Logging.Folder}", InfoBarSeverity.Error);
            RememberRun(RunOutcome.Failed, "The report stopped unexpectedly.");
        }
        finally { SetBusy(false); _cts?.Dispose(); _cts = null; }
    }

    void SetBusy(bool busy)
    {
        Inputs.IsEnabled = !busy;
        StartButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        Busy.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Updates the status line and tells Narrator (LiveSetting alone is not announced for TextBlock changes).</summary>
    void Announce(string text)
    {
        Status.Text = text;
        (UIElementAutomationPeer.FromElement(Status) ?? UIElementAutomationPeer.CreatePeerForElement(Status))
            ?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    void Cancel_Click(object sender, RoutedEventArgs e) { _cts?.Cancel(); CancelButton.IsEnabled = false; Announce("Stopping after the current step..."); }

    void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (_report is not null && File.Exists(_report)) Process.Start(new ProcessStartInfo(_report) { UseShellExecute = true });
    }

    void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_case is not null) Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), _case);
    }

    void Show(string title, string message, InfoBarSeverity severity)
    {
        Result.Title = title; Result.Message = message; Result.Severity = severity; Result.IsOpen = true;
    }
}
