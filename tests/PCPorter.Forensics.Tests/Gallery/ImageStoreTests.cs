using PCPorter.Forensics.Gallery;

namespace PCPorter.Forensics.Tests.Gallery;

public class ImageStoreTests : IDisposable
{
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-store").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 7, 7, 7];

    [Fact]
    public void An_existing_file_with_the_same_content_counts_as_stored()
    {
        var first = new ImageStore(_dir).Save(Png, "png");
        var second = new ImageStore(_dir).Save(Png, "png");            // e.g. a second store on the same folder
        Assert.Equal(first, second);
        Assert.Single(Directory.GetFiles(_dir));
    }

    [Fact]
    public void A_different_file_under_the_same_name_is_never_trusted()
    {
        var name = new ImageStore(_dir).Save(Png, "png");
        File.WriteAllBytes(Path.Combine(_dir, name), [1, 2, 3]);       // planted
        Assert.Throws<IOException>(() => new ImageStore(_dir).Save(Png, "png"));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(Path.Combine(_dir, name)));
    }
}
