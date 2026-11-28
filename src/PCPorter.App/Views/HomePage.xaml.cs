using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using Microsoft.Win32;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Case;
using PCPorter.Core.Security;
using Serilog;

namespace PCPorter.App.Views;

public partial class HomePage : Page
{
    public HomePage() => InitializeComponent();

    /// <summary>Opens Web history; that page links to Images viewed.</summary>
    void History_Click(object sender, RoutedEventArgs e) =>
        (Application.Current.MainWindow as MainWindow)?.Nav.Navigate(typeof(HistoryPage));

    /// <summary>Backup and restore are not built yet: say so plainly and point at what already helps with a move.</summary>
    void Move_Click(object sender, RoutedEventArgs e) =>
        MessageBox.Show("Backup and restore are still being built.\n\nFor now, run \"Check health and security\" on the old PC: its report lists every app to install again on the new PC and where to get it.",
            "Move to my new PC", MessageBoxButton.OK, MessageBoxImage.Information);

    void Health_Click(object sender, RoutedEventArgs e) =>
        (Application.Current.MainWindow as MainWindow)?.Nav.Navigate(typeof(ScanPage));

    // ---- Open results from another PC ----

    async void FindCases_Click(object sender, RoutedEventArgs e) => await Search(OtherPcCases.FindOnDrives, "on the connected drives");

    async void BrowseCases_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Where are the results? (the backup drive, or its PCPorter folder)" };
        if (dlg.ShowDialog() != true) return;
        var folder = dlg.FolderName;
        await Search(() => OtherPcCases.FindIn(folder), $"in {folder}");
    }

    /// <summary>Looks off the UI thread (a sleeping USB disk can take seconds to answer) and lists what was found.</summary>
    async Task Search(Func<CaseSearch> find, string where)
    {
        FindCases.IsEnabled = false;
        OpenCase.IsEnabled = false;
        Announce($"Looking {where}...");
        try
        {
            var found = await Task.Run(find);
            Cases.ItemsSource = found.Cases;
            Cases.Visibility = OpenCase.Visibility = found.Cases.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            Cases.SelectedIndex = found.Cases.Count > 0 ? 0 : -1;
            Announce(Summary(found, where, AppFolders.IsElevated));
        }
        finally { FindCases.IsEnabled = true; }
    }

    /// <summary>The line under the list: what was found, and what to do when results are locked.</summary>
    public static string Summary(CaseSearch found, string where, bool elevated)
    {
        var locked = found.Unreadable.Count > 0 && !elevated
            ? " Some results are locked to another account: start PCPorter as administrator to see them." : "";
        return found.Cases.Count switch
        {
            0 when locked.Length > 0 => "PCPorter results were found, but they are locked to another account. Start PCPorter as administrator to open them.",
            0 => $"No PCPorter results were found {where}. Connect the backup drive and try again, or use \"Look in a folder...\".",
            1 => "1 set of results found. Pick it and press \"Open these results\"." + locked,
            var n => $"{n} sets of results found, newest first. Pick one and press \"Open these results\"." + locked,
        };
    }

    void Cases_SelectionChanged(object sender, SelectionChangedEventArgs e) => OpenCase.IsEnabled = Cases.SelectedItem is FoundCase;

    void OpenCase_Click(object sender, RoutedEventArgs e)
    {
        if (Cases.SelectedItem is not FoundCase c || WindowsIdentity.GetCurrent().User is not { } me) return;
        if (!OtherPcCases.CanRead(c.Path, me))
        {
            var account = WindowsIdentity.GetCurrent().Name;
            var answer = MessageBox.Show(
                $"These results were saved by PCPorter on {c.ComputerName}, and only that PC's account can open them.\n\n" +
                $"Let this account ({account}) read them? Nobody else gets access, and nothing in the results is changed.",
                "Open results from another PC", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) { Announce("Nothing was changed."); return; }
            try
            {
                OtherPcCases.GrantRead(c.Path, me);
                Log.Information("gave the current account read access to a case folder from another PC");
            }
            catch (CaseLocationRejectedException ex) { Announce(ex.Message); return; }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception or IOException
                                           or InvalidOperationException)
            {
                Log.Warning(ex, "could not give read access to a case folder");
                Announce(AppFolders.IsElevated
                    ? $"PCPorter could not open these results for this account ({ex.Message})"
                    : "Start PCPorter as administrator to open results saved by another PC's account.");
                return;
            }
        }
        Announce(CaseLinks.OpenCaseFolder(c.Path) ? "Opened the results in File Explorer." : "The results folder could not be opened.");
    }

    /// <summary>Updates the status line and tells Narrator (LiveSetting alone is not announced for TextBlock changes).</summary>
    void Announce(string text)
    {
        CasesStatus.Text = text;
        (UIElementAutomationPeer.FromElement(CasesStatus) ?? UIElementAutomationPeer.CreatePeerForElement(CasesStatus))
            ?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }
}
