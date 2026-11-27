using System.Windows;
using System.Windows.Controls;

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
}
