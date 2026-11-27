using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using PCPorter.App.Infrastructure;

namespace PCPorter.App.Views;

public partial class AboutPage : Page
{
    public AboutPage()
    {
        InitializeComponent();
        var version = Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        VersionText.Text = $"Version {version}  -  .NET {Environment.Version}";
    }

    void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(Logging.Folder);
        Process.Start("explorer.exe", Logging.Folder);
    }
}
