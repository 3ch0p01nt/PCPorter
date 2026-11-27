using System.Security.Principal;
using PCPorter.Core.Snapshots;

namespace PCPorter.Core.Tests.Snapshots;

/// <summary>Runs only in an elevated test session; skipped otherwise.</summary>
public sealed class AdminFactAttribute : FactAttribute
{
    public AdminFactAttribute()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "Requires an elevated (administrator) test run.";
    }
}

public class VssSnapshotProviderTests
{
    const string Device = @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9";

    [AdminFact]
    [Trait("Category", "Admin")]
    public void Snapshot_reads_a_locked_file_and_cleans_up()
    {
        // Our own harmless temp file, held open exclusively so a normal read would fail.
        var path = Path.Combine(Path.GetTempPath(), $"pcporter-vss-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "snapshot test");
        string device;
        try
        {
            using var locker = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.Throws<IOException>(() => File.ReadAllText(path));
            using (var snap = new VssSnapshotProvider().Create(Path.GetPathRoot(path)!))
            {
                device = snap.DeviceRoot;
                Assert.Equal("snapshot test", File.ReadAllText(snap.Map(path)));
            }
            Assert.False(File.Exists(VssSnapshotProvider.MapPath(device, Path.GetPathRoot(path)!, path)));   // snapshot deleted
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Map_builds_snapshot_path() =>
        Assert.Equal(Device + @"\Users\bob\file.txt", VssSnapshotProvider.MapPath(Device, @"C:\", @"C:\Users\bob\file.txt"));

    [Fact]
    public void Map_is_case_insensitive_and_handles_root() =>
        Assert.Equal(Device + "\\", VssSnapshotProvider.MapPath(Device, @"c:\", @"C:\"));

    [Fact]
    public void Map_rejects_paths_on_another_volume() =>
        Assert.Throws<ArgumentException>(() => VssSnapshotProvider.MapPath(Device, @"C:\", @"D:\Users\bob\file.txt"));

    [Fact]
    public void Map_rejects_prefix_that_is_not_a_folder_boundary() =>
        Assert.Throws<ArgumentException>(() => VssSnapshotProvider.MapPath(Device, @"C:\Data", @"C:\DataX\file.txt"));
}
