using PCPorter.Forensics.Gallery;

namespace PCPorter.Forensics.Tests.Gallery;

public class OriginalLocatorTests
{
    sealed class FakeProbe : IFileProbe
    {
        public HashSet<string> Drives { get; } = new(StringComparer.OrdinalIgnoreCase) { @"C:\" };
        public Dictionary<string, string[]> Folders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Denied { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, uint> Serials { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Listings { get; private set; }
        public int DriveChecks { get; private set; }

        public bool DriveAvailable(string root) { DriveChecks++; return Drives.Contains(root); }
        public uint? VolumeSerial(string root) => Serials.TryGetValue(root, out var s) ? s : null;
        public IReadOnlySet<string>? List(string folder)
        {
            Listings++;
            if (Denied.Contains(folder)) throw new UnauthorizedAccessException();
            return Folders.TryGetValue(folder, out var names) ? names.ToHashSet(StringComparer.OrdinalIgnoreCase) : null;
        }
        public FileTimes? Times(string path) => null;
    }

    [Fact]
    public void Exists_deleted_unreachable_unknown()
    {
        var p = new FakeProbe();
        p.Folders[@"C:\Pics"] = ["cat.jpg", "Album"];
        p.Folders[@"C:\"] = ["Pics"];
        p.Denied.Add(@"C:\Users\other");
        var l = new OriginalLocator(p);

        Assert.Equal(OriginalStatus.Exists, l.Locate(@"C:\Pics\CAT.JPG"));          // case-insensitive
        Assert.Equal(OriginalStatus.Exists, l.Locate(@"C:\Pics\Album"));            // folder
        Assert.Equal(OriginalStatus.Deleted, l.Locate(@"C:\Pics\dog.jpg"));
        Assert.Equal(OriginalStatus.FolderGone, l.Locate(@"C:\Pics\Gone\x.jpg"));   // folder moved, renamed or deleted: not proof the file was
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"C:\Users\other\x.jpg")); // access denied
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"E:\Pics\x.jpg"));       // drive not present
        Assert.Equal(OriginalStatus.Unknown, l.Locate(null));
        Assert.Equal(OriginalStatus.Unknown, l.Locate("   "));
    }

    [Fact]
    public void Network_paths_are_unreachable_without_any_probe()
    {
        var p = new FakeProbe();
        var l = new OriginalLocator(p);
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"\\server\share\Pics\x.jpg"));
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"//server/share/x.jpg"));
        Assert.Equal(0, p.Listings);
        Assert.Equal(0, p.DriveChecks);
    }

    [Fact]
    public void A_different_disk_in_the_same_drive_letter_is_unreachable()
    {
        var p = new FakeProbe();
        p.Drives.Add(@"E:\");
        p.Serials[@"E:\"] = 0x1111;
        p.Folders[@"E:\Pics"] = ["a.jpg"];
        var l = new OriginalLocator(p);
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"E:\Pics\gone.jpg", recordedVolumeSerial: 0x2222));
        Assert.Equal(OriginalStatus.Deleted, l.Locate(@"E:\Pics\gone.jpg", recordedVolumeSerial: 0x1111));
        Assert.Equal(OriginalStatus.Deleted, l.Locate(@"E:\Pics\gone.jpg"));                 // nothing recorded: folder was read
    }

    [Fact]
    public void Each_folder_is_listed_once()
    {
        var p = new FakeProbe();
        p.Folders[@"C:\Pics"] = ["a.jpg"];
        var l = new OriginalLocator(p);
        for (int i = 0; i < 100; i++) l.Locate($@"C:\Pics\file{i}.jpg");
        Assert.Equal(1, p.Listings);
    }
}
