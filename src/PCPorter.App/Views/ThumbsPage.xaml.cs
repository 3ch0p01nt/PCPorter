using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Case;
using PCPorter.Core.Config;
using PCPorter.Forensics.Gallery;
using PCPorter.Reports;
using Serilog;
using Wpf.Ui.Controls;

namespace PCPorter.App.Views;

public partial class ThumbsPage : Page
{
    CancellationTokenSource? _cts;
    string? _reportPath, _caseFolder;
    readonly bool _elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    const string MemoryKey = "thumbs";

    public ThumbsPage()
    {
        InitializeComponent();
        var memory = Remembered.Pages.Get(MemoryKey);
        if (string.IsNullOrWhiteSpace(memory.SaveFolder)) _ = WindowsDrives.SuggestSaveFolderAsync(() => OutFolder.Text, s => OutFolder.Text = s);
        else OutFolder.Text = memory.SaveFolder;
        Remembered.RestoreOptions(memory, ("webCaches", WebCaches), ("fullIndex", FullIndex), ("allUsers", AllUsers));
        AllUsers.IsEnabled = _elevated;
        if (!_elevated) { AllUsers.IsChecked = false; AllUsers.ToolTip = "Needs PCPorter to run as administrator."; }
        if (Remembered.LastRunOf(MemoryKey) is { } last)
        {
            _reportPath = last.ReportPath;
            Status.Text = PageMemoryStore.Describe("Last gallery", last);
            OpenReport.Visibility = Visibility.Visible;
        }
    }

    void RememberRun(RunOutcome outcome, string summary) =>
        Remembered.Pages.Update(MemoryKey, m => m with { LastRun = new LastRun(DateTime.Now, outcome, summary, _reportPath, _caseFolder) });

    void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Where should the report be saved?", InitialDirectory = Directory.Exists(OutFolder.Text) ? OutFolder.Text : null };
        if (dlg.ShowDialog() == true) OutFolder.Text = dlg.FolderName;
    }

    async void Start_Click(object sender, RoutedEventArgs e)
    {
        var target = OutFolder.Text.Trim();
        var check = CaseLocation.Check(target);
        if (!check.IsAllowed) { Show("Pick another folder", check.Reason!, InfoBarSeverity.Warning); return; }

        var settings = new GalleryJobFactory.Settings(AllUsers: AllUsers.IsChecked == true && _elevated,
            Web: WebCaches.IsChecked == true, FullIndex: FullIndex.IsChecked == true);
        Remembered.Pages.Update(MemoryKey, m => m with
        {
            SaveFolder = target,
            Options = Remembered.Options(m, ("webCaches", WebCaches, true), ("fullIndex", FullIndex, true), ("allUsers", AllUsers, _elevated)),
        });
        _reportPath = _caseFolder = null;
        SetBusy(true);
        Result.IsOpen = false;
        OpenReport.Visibility = Visibility.Collapsed;
        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(m => Status.Text = PCPorter.Core.Security.Redactor.Redact(m));   // UI thread stays free: the job runs on a worker
        try
        {
            var cts = _cts;
            var r = await RunningJobs.Instance.Track(cts, Task.Run(() => ThumbnailJob.Run(target, progress: progress,
                options: GalleryJobFactory.Options(settings, _elevated, progress), ct: cts.Token)));
            _reportPath = r.ReportPath; _caseFolder = r.CaseFolder;
            var items = r.Scan.Items;
            var msg = $"{items.Count(i => i.Kind == "thumbnail"):N0} thumbnails ({items.Count(i => i.Status == OriginalStatus.Deleted):N0} with deleted originals), " +
                      $"{items.Count(i => i.Kind == "web"):N0} web images, {items.Count(i => i.Kind == "screenshot"):N0} screenshots, {items.Count(i => i.Kind == "opened"):N0} opened files.";
            var gaps = r.Scan.Warnings.Count;   // parts not read; the folder warnings are shown as they are, below
            var warnings = gaps + r.FolderWarnings.Count;
            var message = msg + (gaps > 0 ? $" {gaps} part{(gaps == 1 ? "" : "s")} could not be read; see the notes in the report." : "");
            Show("Gallery ready", FolderWarnings.Append(message, r.FolderWarnings), warnings > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success);
            OpenReport.Visibility = CaseLinks.IsReport(_reportPath) ? Visibility.Visible : Visibility.Collapsed;
            Status.Text = r.ReportPath;
            RememberRun(warnings > 0 ? RunOutcome.Partial : RunOutcome.Ok, message);
        }
        catch (OperationCanceledException)
        {
            Show("Cancelled", "Nothing was changed on this PC. A partly written case folder may remain.", InfoBarSeverity.Informational);
            RememberRun(RunOutcome.Stopped, "Stopped before the gallery was written.");
        }
        catch (Exception ex)
        {
            var err = JobErrors.Describe(ex, "the gallery", Infrastructure.Logging.Folder);
            if (err.Kind == JobErrorKind.CantStart) Show(err.Title, err.Message, InfoBarSeverity.Warning);
            else
            {
                Log.Error(ex, "gallery failed");
                Show(err.Title, err.Message, InfoBarSeverity.Error);
                RememberRun(RunOutcome.Failed, $"{err.Title}. {err.Message}");
            }
        }
        finally { SetBusy(false); _cts?.Dispose(); _cts = null; }
    }

    void Cancel_Click(object sender, RoutedEventArgs e) { _cts?.Cancel(); Status.Text = "Cancelling..."; }

    void OpenReport_Click(object sender, RoutedEventArgs e) => CaseLinks.OpenReport(_reportPath);

    void SetBusy(bool busy)
    {
        StartButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        Busy.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        OutFolder.IsEnabled = WebCaches.IsEnabled = FullIndex.IsEnabled = !busy;
        AllUsers.IsEnabled = !busy && _elevated;
    }

    void Show(string title, string message, InfoBarSeverity severity)
    {
        Result.Title = title;
        Result.Message = message;
        Result.Severity = severity;
        Result.IsOpen = true;
    }
}
