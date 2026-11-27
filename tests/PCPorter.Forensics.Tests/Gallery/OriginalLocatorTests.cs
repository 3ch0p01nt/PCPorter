using PCPorter.Forensics.Gallery;

namespace PCPorter.Forensics.Tests.Gallery;

public class OriginalLocatorTests
{
    sealed class FakeProbe : IFileProbe
    {
        public HashSet<string> Drives { get; } = new(StringComparer.OrdinalIgnoreCase) { @"C:\" };
        public Dictionary<string, string[]> Folders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Denied { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Listings { get; private set; }

        public bool DriveAvailable(string root) => Drives.Contains(root);
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
        Assert.Equal(OriginalStatus.Deleted, l.Locate(@"C:\Pics\Gone\x.jpg"));      // whole folder deleted, parent readable
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"C:\Users\other\x.jpg")); // access denied
        Assert.Equal(OriginalStatus.Unreachable, l.Locate(@"E:\Pics\x.jpg"));       // drive not present
        Assert.Equal(OriginalStatus.Unknown, l.Locate(null));
        Assert.Equal(OriginalStatus.Unknown, l.Locate("   "));
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
