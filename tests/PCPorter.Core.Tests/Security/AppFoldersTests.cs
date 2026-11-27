using System.Diagnostics;
using PCPorter.Core.Security;

namespace PCPorter.Core.Tests.Security;

public sealed class AppFoldersTests : IDisposable
{
    readonly string _programData = Directory.CreateTempSubdirectory("pcporter-programdata").FullName;
    public void Dispose()
    {
        var link = Path.Combine(_programData, "PCPorter");
        if (Directory.Exists(link) && new DirectoryInfo(link).Attributes.HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(link);
        try { Directory.Delete(_programData, true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    [Fact]
    public void Elevated_run_never_falls_back_to_a_user_writable_folder_when_the_folder_is_a_link()
    {
        var target = Directory.CreateDirectory(Path.Combine(_programData, "attacker")).FullName;
        var link = Path.Combine(_programData, "PCPorter");
        using (var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                   $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false })) p!.WaitForExit();
        var ex = Assert.Throws<UnsafeAppFolderException>(() => AppFolders.For("state", elevated: true, _programData));
        Assert.Contains("could not make its working folder", ex.Message);
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
    }

    [Fact]
    public void Elevated_run_fails_closed_when_the_folder_cannot_be_locked()
    {
        if (AppFolders.IsElevated) return;                         // an admin CAN lock it; this checks the failure path
        Assert.Throws<UnsafeAppFolderException>(() => AppFolders.For("state", elevated: true, _programData));
    }

    [Fact]
    public void Not_elevated_uses_local_app_data()
    {
        var path = AppFolders.For("pcporter-test", elevated: false, _programData);
        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), path);
        Directory.Delete(path);
    }
}
