using System.Diagnostics;
using PCPorter.Core.Case;
using PCPorter.Core.IO;

namespace PCPorter.Core.Tests.Case;

/// <summary>A pretend PC: every drive is a local NTFS disk unless a test says otherwise; only roots exist.</summary>
sealed class FakeProbe : ILocationProbe
{
    public Dictionary<string, DriveType> Types = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Devices = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, (string?, string?)> Volumes = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, EntryInfo> Entries = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Finals = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Roots = [];
    public HashSet<string> ReadOnly = new(StringComparer.OrdinalIgnoreCase);

    public static readonly EntryInfo Folder = new(FileAttributes.Directory, 0);

    public DriveType DriveType(string root) => Types.GetValueOrDefault(root, System.IO.DriveType.Fixed);
    public string? DosDeviceTarget(string drive) => Devices.GetValueOrDefault(drive, @"\Device\HarddiskVolume3");
    public (string? Label, string? FileSystem) Volume(string root) => Volumes.GetValueOrDefault(root, ("Local Disk", "NTFS"));
    public EntryInfo? Entry(string path) => path.Length == 3 || Entries.ContainsKey(path) ? Entries.GetValueOrDefault(path, Folder) : null;
    public string? FinalPath(string path) => Finals.GetValueOrDefault(path, path);
    public string? NtPath(string path) => @"\Device\HarddiskVolume3\" + path[3..];
    public IEnumerable<string> SyncRoots() => Roots;
    public bool? IsReadOnlyVolume(string root) => ReadOnly.Contains(root);
}

public class CaseLocationTests
{
    static readonly Dictionary<string, string?> Env = new()
    {
        ["OneDrive"] = @"C:\Users\bob\OneDrive - Contoso",
        ["OneDriveConsumer"] = @"C:\Users\bob\OneDrive",
    };
    static CaseLocationResult Check(string p, FakeProbe? probe = null) =>
        CaseLocation.Check(p, n => Env.GetValueOrDefault(n), probe ?? new FakeProbe(), scannedRoot: null);

    [Theory]
    [InlineData(@"C:\Users\bob\OneDrive - Contoso\Cases")]
    [InlineData(@"c:\users\bob\onedrive\cases")]
    [InlineData(@"C:\Users\bob\Dropbox\cases")]
    [InlineData(@"C:\Users\bob\Dropbox (Contoso)\cases")]
    [InlineData(@"C:\Users\bob\Google Drive\cases")]
    [InlineData(@"\\server\share\cases")]
    [InlineData(@"//server/share/cases")]
    [InlineData(@"\\?\UNC\server\share\cases")]
    [InlineData(@"\\.\UNC\server\share\cases")]
    [InlineData(@"\\?\C:\Users\bob\OneDrive\cases")]
    [InlineData(@"D:\Users\alice\OneDrive - Fabrikam\Cases")]   // another user's OneDrive (env vars point elsewhere)
    [InlineData(@"D:\Users\alice\OneDrive\Cases")]
    public void Synced_or_network_folders_are_rejected(string path)
    {
        var r = Check(path);
        Assert.False(r.IsAllowed);
        Assert.False(string.IsNullOrWhiteSpace(r.Reason));
    }

    [Theory]
    [InlineData(@"E:\PCPorter")]
    [InlineData(@"C:\PCPorterDev")]
    [InlineData(@"C:\Users\bob\OneDriveNotReally\x")]
    [InlineData(@"\\?\D:\Cases\a\very\long\path")]                 // long local path: not a network path
    [InlineData(@"E:\")]
    public void Local_or_external_folders_are_allowed(string path) => Assert.True(Check(path).IsAllowed, Check(path).Reason);

    [Theory]
    [InlineData(@"F:\")]
    [InlineData(@"F:\PCPorter
ew")]
    public void A_write_protected_drive_is_refused_up_front(string path)
    {
        var probe = new FakeProbe();
        probe.ReadOnly.Add(@"F:\");
        var r = Check(path, probe);
        Assert.False(r.IsAllowed);
        Assert.Contains("write-protected", r.Reason);
        Assert.True(Check(@"E:\PCPorter", probe).IsAllowed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("cases")]
    [InlineData(@"..\cases")]
    [InlineData(@"C:cases")]
    [InlineData(@"\cases")]
    public void Empty_or_relative_paths_ask_for_a_full_path(string path)
    {
        var r = CaseLocation.Check(path);                           // the real API: must not throw
        Assert.False(r.IsAllowed);
        Assert.StartsWith("Pick a full folder path", r.Reason);
    }

    [Theory]
    [InlineData(@"//server/share/x")]
    [InlineData(@"\\?\UNC\server\share")]
    public void Network_paths_are_refused_without_touching_the_network(string path) =>
        Assert.StartsWith("Network folders are not allowed", CaseLocation.Check(path).Reason);

    [Fact]
    public void Mapped_network_drive_is_rejected()
    {
        var byType = new FakeProbe { Types = { [@"Z:\"] = DriveType.Network } };
        Assert.StartsWith("Network", Check(@"Z:\cases", byType).Reason);
        var byDevice = new FakeProbe { Devices = { ["Y:"] = @"\Device\LanmanRedirector\;Y:0000000000012345\server\share" } };
        Assert.StartsWith("Network", Check(@"Y:\cases", byDevice).Reason);
    }

    [Fact]
    public void Subst_drive_is_checked_where_it_really_points()
    {
        var toOneDrive = new FakeProbe { Devices = { ["S:"] = @"\??\C:\Users\bob\OneDrive" } };
        Assert.Contains("OneDrive", Check(@"S:\cases", toOneDrive).Reason);

        var toLibrary = new FakeProbe { Devices = { ["T:"] = @"\??\C:\Users\bob\Contoso\Site - Documents" }, Roots = { @"C:\Users\bob\Contoso\Site - Documents" } };
        Assert.Contains("cloud-synced", Check(@"T:\x", toLibrary).Reason);

        var toShare = new FakeProbe { Devices = { ["U:"] = @"\??\UNC\server\share" } };
        Assert.StartsWith("Network", Check(@"U:\x", toShare).Reason);

        Assert.True(Check(@"V:\x", new FakeProbe { Devices = { ["V:"] = @"\??\D:\Cases" } }).IsAllowed);
    }

    [Fact]
    public void Registered_sync_roots_are_rejected_whatever_their_name()
    {
        var probe = new FakeProbe { Roots = { @"C:\Users\bob\Contoso\Site - Documents", @"D:\Sync\Work\" } };
        Assert.Contains("cloud-synced", Check(@"C:\Users\bob\Contoso\Site - Documents\Cases", probe).Reason);
        Assert.Contains("cloud-synced", Check(@"d:\sync\work", probe).Reason);         // relocated OneDrive
        Assert.True(Check(@"D:\Sync\Workshop", probe).IsAllowed);
    }

    [Fact]
    public void Cloud_placeholder_or_link_on_the_way_is_rejected()
    {
        var cloud = new FakeProbe { Entries = { [@"C:\Data"] = new(FileAttributes.Directory | FileAttributes.ReparsePoint, 0x9000701A) } };
        Assert.Contains("cloud-synced", Check(@"C:\Data\Cases\new", cloud).Reason);

        var pinned = new FakeProbe { Entries = { [@"C:\Data"] = new(FileAttributes.Directory | (FileAttributes)0x80000, 0) } };
        Assert.Contains("cloud-synced", Check(@"C:\Data\Cases", pinned).Reason);

        var junction = new FakeProbe { Entries = { [@"C:\Data"] = new(FileAttributes.Directory | FileAttributes.ReparsePoint, 0xA0000003) } };
        Assert.Contains("is a link", Check(@"C:\Data\Cases", junction).Reason);
    }

    [Fact]
    public void Real_path_on_the_network_is_rejected()
    {
        var probe = new FakeProbe { Entries = { [@"C:\Data"] = FakeProbe.Folder }, Finals = { [@"C:\Data"] = @"\\server\share\Data" } };
        Assert.StartsWith("Network", Check(@"C:\Data\Cases", probe).Reason);
    }

    [Fact]
    public void Google_drive_virtual_drive_is_rejected()
    {
        Assert.Contains("Google Drive", Check(@"G:\Cases", new FakeProbe { Volumes = { [@"G:\"] = ("Google Drive", "FAT32") } }).Reason);
        var unlabelled = new FakeProbe { Volumes = { [@"H:\"] = ("", "FAT32") }, Entries = { [@"H:\My Drive"] = FakeProbe.Folder } };
        Assert.Contains("Google Drive", Check(@"H:\Cases", unlabelled).Reason);
        Assert.True(Check(@"I:\Cases", new FakeProbe { Volumes = { [@"I:\"] = ("BACKUP", "FAT32") } }).IsAllowed);   // an ordinary USB stick
    }

    [Fact]
    public void Real_subst_drive_to_a_synced_folder_is_rejected()
    {
        var letter = "PQRSTUVWXY".Select(c => c + ":").FirstOrDefault(l => !Directory.Exists(l + "\\"));
        if (letter is null) return;
        var target = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pcporter-subst-{Guid.NewGuid():N}", "Dropbox")).FullName;
        try
        {
            Subst($"{letter} \"{target}\"");
            Assert.True(Directory.Exists(letter + "\\"));
            var r = CaseLocation.Check(letter + @"\cases", _ => null);
            Assert.False(r.IsAllowed);
            Assert.Contains("Dropbox", r.Reason);
        }
        finally
        {
            Subst($"{letter} /d");
            Directory.Delete(Path.GetDirectoryName(target)!, true);
        }
    }

    [Fact]
    public void Registered_sync_roots_on_this_pc_are_rejected()
    {
        foreach (var root in WindowsProbe.Instance.SyncRoots().Where(Directory.Exists).Take(3))
            Assert.False(CaseLocation.Check(Path.Combine(root, "pcporter-never-created"), _ => null).IsAllowed, root);
    }

    [Fact]
    public void Junction_on_the_way_is_rejected()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-loc").FullName;
        var link = Path.Combine(root, "link");
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(root, "target")).FullName;
            Junction(link, target);
            Assert.Contains("is a link", CaseLocation.Check(Path.Combine(link, "cases"), _ => null).Reason);
            Assert.True(CaseLocation.Check(Path.Combine(target, "cases"), _ => null).IsAllowed);
        }
        finally { if (Directory.Exists(link)) Directory.Delete(link); Directory.Delete(root, true); }
    }

    [Fact]
    public void Folder_on_the_scanned_drive_is_rejected_however_it_is_reached()
    {
        var scan = Directory.CreateTempSubdirectory("pcporter-scan").FullName;
        var other = Directory.CreateTempSubdirectory("pcporter-save").FullName;
        try
        {
            var nt = FileIdentity.NtPath(scan)!;
            var device = @"\\?\GLOBALROOT" + nt;                  // the same folder named another way
            Assert.Contains("drive being checked", CaseLocation.Check(Path.Combine(scan, "out"), scan, _ => null).Reason);
            Assert.Contains("drive being checked", CaseLocation.Check(Path.Combine(scan, "out"), device, _ => null).Reason);
            Assert.Contains("drive being checked", CaseLocation.Check(@"\\?\" + Path.Combine(scan, "a", "b"), scan.ToUpperInvariant(), _ => null).Reason);
            Assert.True(CaseLocation.Check(Path.Combine(other, "out"), device, _ => null).IsAllowed);
            Assert.True(CaseLocation.Check(Path.Combine(other, "out"), null, _ => null).IsAllowed);
            Assert.Contains("could not check", CaseLocation.Check(Path.Combine(other, "out"), @"\\?\GLOBALROOT\Device\PCPorterNoSuchVolume\", _ => null).Reason);
        }
        finally { Directory.Delete(scan, true); Directory.Delete(other, true); }
    }

    [Fact]
    public void Whole_volume_scanned_rejects_any_folder_on_it()
    {
        var temp = Path.GetTempPath();
        var root = Path.GetPathRoot(temp)!;
        Assert.Contains("drive being checked", CaseLocation.Check(Path.Combine(temp, "pcporter-x"), root, _ => null).Reason);
    }

    internal static void Junction(string link, string target)
    {
        using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false });
        p!.WaitForExit();
        Assert.True(Directory.Exists(link));
    }

    static void Subst(string args)
    {
        using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "subst.exe"), args) { CreateNoWindow = true, UseShellExecute = false });
        p!.WaitForExit();
    }
}
