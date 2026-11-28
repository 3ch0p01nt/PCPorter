using System.Diagnostics;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Offline;
using PCPorter.Collectors.Signing;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests;

/// <summary>
/// A link planted on an old drive (junction or symlink, possibly to a network share) must never be followed by an
/// existence check. A junction to a local "outside" folder stands in for the share: what is behind it must not count.
/// </summary>
public sealed class SourcePresenceTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-presence").FullName + "\\";
    readonly string _outside = Directory.CreateTempSubdirectory("pcporter-outside").FullName;
    readonly List<string> _links = [];

    public void Dispose()
    {
        foreach (var l in _links) try { Directory.Delete(l); } catch (IOException) { }
        foreach (var d in new[] { _root, _outside }) try { Directory.Delete(d, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Junction at <paramref name="relative"/> under the fake drive pointing to the outside folder. False if mklink is unavailable.</summary>
    bool Link(string relative)
    {
        var link = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "/c", "mklink", "/J", link, _outside }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit(10000);
        if (p.ExitCode != 0 || !Directory.Exists(link)) return false;
        _links.Add(link);
        return true;
    }

    string Outside(string relative, string text = "x")
    {
        var p = Path.Combine(_outside, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, text);
        return p;
    }

    [Fact]
    public void Present_missing_and_behind_a_link_are_told_apart()
    {
        File.WriteAllText(Path.Combine(_root, "real.txt"), "x");
        Outside("behind.txt");
        if (!Link("lnk")) return;
        using (SourceFiles.Confine(_root))
        {
            Assert.Equal(Presence.Present, SourcePresence.Of(Path.Combine(_root, "real.txt")));
            Assert.Equal(Presence.Missing, SourcePresence.Of(Path.Combine(_root, "nope", "x.exe")));
            Assert.Equal(Presence.NotFollowed, SourcePresence.Of(Path.Combine(_root, "lnk", "behind.txt")));
            Assert.Equal(Presence.NotFollowed, SourcePresence.Of(Path.Combine(_root, "lnk", "not-there.txt")));   // unknown, never "missing"
            Assert.Equal(Presence.NotFollowed, SourcePresence.Of(@"\\server\share\x.exe"));
            Assert.False(SourcePresence.IsFile(Path.Combine(_root, "lnk", "behind.txt")));
        }
    }

    [Fact]
    public void A_startup_program_behind_a_link_is_not_checked_and_not_called_missing()
    {
        var exe = Path.Combine(_outside, "cmd.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), exe);
        if (!Link("Tools")) return;
        using (SourceFiles.Confine(_root))
        {
            var via = Path.Combine(_root, "Tools", "cmd.exe");
            var checker = new AuthenticodeChecker(new OfflineCatalogIndex(_root));
            Assert.Equal(SignatureStatus.NotChecked, checker.Check(via).Status);
            Assert.Equal(0, checker.Verifications);                                                   // never opened
            Assert.Equal(SignatureStatus.NotChecked, checker.Check(Path.Combine(_root, "Tools", "gone.exe")).Status);   // behind a link: unknown, not "missing"
            Assert.Equal(SignatureStatus.NotChecked, new NoSignatureChecker().Check(Path.Combine(_root, "Tools", "gone.exe")).Status);
            Assert.Equal(SignatureStatus.FileMissing, new NoSignatureChecker().Check(Path.Combine(_root, "gone.exe")).Status);
        }
    }

    [Fact]
    public void A_linked_winget_folder_is_not_read()
    {
        var index = Path.Combine(_outside, @"Microsoft.Winget.Source_2025.1.1.1_neutral__8wekyb3d8bbwe\Public\index.db");
        Directory.CreateDirectory(Path.GetDirectoryName(index)!);
        WingetCatalogs.CreateV2(index, new CatalogPackage("Contoso.App"));
        if (!Link(@"Program Files\WindowsApps")) return;
        using (SourceFiles.Confine(_root))
        {
            Assert.Null(WingetIndex.Open(new FakeSystemSource(_root), out var why));
            Assert.NotNull(why);
        }
    }

    [Fact]
    public void A_linked_hibernation_file_is_unknown_not_missing()
    {
        if (!Link("hiberfil.sys")) return;                                   // a link where the file should be
        Assert.Null(VolumeSafety.IsHibernated(_root));                       // unknown; before: "not hibernated"
        Assert.False(VolumeSafety.IsHibernated(_outside + "\\"));            // really missing: not hibernated
    }

    [Fact]
    public void Opening_a_drive_whose_System32_is_a_link_refuses_it()
    {
        Outside(@"config\SOFTWARE");
        if (!Link(@"Windows\System32")) return;
        Assert.Throws<PCPorter.Core.SourceRejectedException>(() => new OfflineSource(_root, runningWindowsDrive: "Q:\\"));
    }

    [Fact]
    public void The_drive_picker_does_not_follow_a_linked_Windows_folder()
    {
        Outside(@"System32\config\SOFTWARE");
        if (!Link("Windows")) return;
        var scan = new OfflineVolumeFinder(new FakeWmiClient(), drives: () => [_root], runningWindowsDrive: "Q:\\", readOs: _ => ("Windows 10", "19045")).Find();
        Assert.Empty(scan.Volumes);
    }
}
