using PCPorter.Core.Security;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace PCPorter.App;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        Title = AppTitle.Title = TitleFor(AppFolders.IsElevated);
        SystemThemeWatcher.Watch(this);   // follow Windows light/dark mode and accent color
        Loaded += (_, _) => Nav.Navigate(typeof(Views.HomePage));
    }

    /// <summary>The title says "administrator" only when PCPorter really runs as administrator.</summary>
    public static string TitleFor(bool elevated) => elevated ? "PCPorter  -  running as administrator" : "PCPorter";
}
