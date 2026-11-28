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
        Assert.Single(Directory.GetFiles(_dir, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void Pictures_are_spread_over_subfolders_so_fat32_folders_never_fill()
    {
        // FAT32 holds about 21,800 such names in one folder: 256 subfolders by hash prefix keep each one small.
        var store = new ImageStore(_dir);
        var names = Enumerable.Range(0, 64).Select(i => store.Save(Png.Append((byte)i).ToArray(), "png")).ToList();
        Assert.All(names, n => Assert.Matches("^[0-9a-f]{2}/[0-9a-f]{16}\\.png$", n));
        Assert.All(names, n => Assert.StartsWith(n[..2], n[3..]));
        Assert.All(names, n => Assert.True(File.Exists(Path.Combine(_dir, n))));
        Assert.True(names.Select(n => n[..2]).Distinct().Count() > 1);
        Assert.Empty(Directory.GetFiles(_dir));                       // nothing directly in the picture folder
    }

    [Fact]
    public void A_different_file_under_the_same_name_is_never_trusted()
    {
        var name = new ImageStore(_dir).Save(Png, "png");
        File.WriteAllBytes(Path.Combine(_dir, name), [1, 2, 3]);       // planted
        Assert.Throws<IOException>(() => new ImageStore(_dir).Save(Png, "png"));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(Path.Combine(_dir, name)));
    }

    // An SVG is a document that can run script when opened from the report folder; the old PC's bytes are never saved as one.
    [Theory]
    [InlineData("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>")]
    [InlineData("<?xml version=\"1.0\"?>\n<svg onload=\"alert(1)\"/>")]
    [InlineData("﻿  <SVG/>")]
    public void Svg_is_saved_as_bin(string svg)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(svg);
        Assert.Equal("bin", ImageStore.ExtensionFor(bytes));
        var name = new ImageStore(_dir).Save(bytes, ImageStore.ExtensionFor(bytes));
        Assert.EndsWith(".bin", name);
        Assert.Empty(Directory.GetFiles(_dir, "*.svg"));
    }

    [Fact]
    public void Real_picture_formats_keep_their_extension()
    {
        Assert.Equal("png", ImageStore.ExtensionFor(Png));
        Assert.Equal("jpg", ImageStore.ExtensionFor([0xFF, 0xD8, 0xFF, 0xE0]));
    }
}
