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
        OutFolder.Text = string.IsNullOrWhiteSpace(memory.SaveFolder) ? SuggestFolder() : memory.SaveFolder;
        Remembered.RestoreOptions(memory, ("webCaches", WebCaches), ("fullIndex", FullIndex), ("allUsers", AllUsers));
        AllUsers.IsEnabled = _elevated;
        if (!_elevated) { AllUsers.IsChecked = false; AllUsers.ToolTip = "Needs PCPorter to run as administrator."; }
        if (Remembered.Pages.RecallLastRun(MemoryKey) is { } last)
        {
            _reportPath = last.ReportPath;
            Status.Text = PageMemoryStore.Describe("Last gallery", last);
            OpenReport.Visibility = Visibility.Visible;
        }
    }

    void RememberRun(RunOutcome outcome, string summary) =>
        Remembered.Pages.Update(MemoryKey, m => m with { LastRun = new LastRun(DateTime.Now, outcome, summary, _reportPath, _caseFolder) });

    /// <summary>First removable drive (the backup drive), else a local folder outside any synced location.</summary>
    static string SuggestFolder()
    {
        var removable = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.DriveType == DriveType.Removable);
        return removable?.RootDirectory.FullName ?? @"C:\PCPorterCases";
    }

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
        var progress = new Progress<string>(m => Status.Text = m);   // UI thread stays free: the job runs on a worker
        try
        {
            var r = await Task.Run(() => ThumbnailJob.Run(target, progress: progress,
                options: GalleryJobFactory.Options(settings, _elevated, progress), ct: _cts.Token));
            _reportPath = r.ReportPath; _caseFolder = r.CaseFolder;
            var items = r.Scan.Items;
            var msg = $"{items.Count(i => i.Kind == "thumbnail"):N0} thumbnails ({items.Count(i => i.Status == OriginalStatus.Deleted):N0} with deleted originals), " +
                      $"{items.Count(i => i.Kind == "web"):N0} web images, {items.Count(i => i.Kind == "screenshot"):N0} screenshots, {items.Count(i => i.Kind == "opened"):N0} opened files.";
            var warnings = r.Scan.Warnings.Count + r.FolderWarnings.Count;
            var message = msg + (warnings > 0 ? $" {warnings} parts could not be read; see the notes in the report." : "");
            Show("Gallery ready", message, warnings > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success);
            OpenReport.Visibility = Visibility.Visible;
            Status.Text = r.ReportPath;
            RememberRun(warnings > 0 ? RunOutcome.Partial : RunOutcome.Ok, message);
        }
        catch (OperationCanceledException)
        {
            Show("Cancelled", "Nothing was changed on this PC. A partly written case folder may remain.", InfoBarSeverity.Informational);
            RememberRun(RunOutcome.Stopped, "Stopped before the gallery was written.");
        }
        catch (CaseLocationRejectedException ex) { Show("Pick another folder", ex.Message, InfoBarSeverity.Warning); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warning(ex, "Gallery job could not write");
            Show("Could not save the report", ex.Message, InfoBarSeverity.Error);
            RememberRun(RunOutcome.Failed, "The gallery could not be saved.");
        }
        finally { SetBusy(false); _cts?.Dispose(); _cts = null; }
    }

    void Cancel_Click(object sender, RoutedEventArgs e) { _cts?.Cancel(); Status.Text = "Cancelling..."; }

    void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (_reportPath is not null && File.Exists(_reportPath))
            Process.Start(new ProcessStartInfo(_reportPath) { UseShellExecute = true });
    }

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
