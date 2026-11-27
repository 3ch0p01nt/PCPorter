using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace PCPorter.App;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        SystemThemeWatcher.Watch(this);   // follow Windows light/dark mode and accent color
        Loaded += (_, _) => Nav.Navigate(typeof(Views.HomePage));
    }
}
