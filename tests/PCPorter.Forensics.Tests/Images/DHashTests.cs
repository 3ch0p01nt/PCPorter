using PCPorter.Forensics.Images;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.Images;

public class DHashTests(ITestOutputHelper output)
{
    private static readonly byte[] Original = ImageTestData.Png(160, 120, (x, y) => ImageTestData.Blobs(x, y, 160, 120));
    private static readonly byte[] Resaved = ImageTestData.Jpeg(120, 90, (x, y) => ImageTestData.Blobs(x, y, 120, 90), quality: 70);
    private static readonly byte[] Different = ImageTestData.Png(160, 120, (x, y) => ImageTestData.Stripes(x, y, 160, 120));

    [Fact]
    public void Identical_pictures_have_distance_zero()
    {
        var a = DHash.Compute(Original);
        var b = DHash.Compute(Original.ToArray());
        Assert.NotNull(a);
        Assert.Equal(0, DHash.Distance(a.Value, b!.Value));
    }

    [Fact]
    public void Resized_and_reencoded_copy_is_close()
    {
        int d = DHash.Distance(DHash.Compute(Original)!.Value, DHash.Compute(Resaved)!.Value);
        output.WriteLine($"resaved distance {d}");
        Assert.True(d < 10, $"distance {d}");
    }

    [Fact]
    public void Different_picture_is_far()
    {
        int d = DHash.Distance(DHash.Compute(Original)!.Value, DHash.Compute(Different)!.Value);
        output.WriteLine($"different distance {d}");
        Assert.True(d > 20, $"distance {d}");
    }

    [Fact]
    public void Undecodable_bytes_give_null()
    {
        Assert.Null(DHash.Compute([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
        Assert.Null(DHash.Compute([]));
        Assert.Null(DHash.Compute(null));
        Assert.Null(DHash.Compute(Original[..40])); // truncated PNG
    }

    static byte[] As(System.Windows.Media.Imaging.BitmapEncoder encoder) =>
        ImageTestData.Encoded(encoder, 160, 120, (x, y) => ImageTestData.Blobs(x, y, 160, 120));

    // The picture bytes come from an old PC: only the four formats Windows decodes with its own built-in codecs are
    // hashed. TIFF and JPEG XR decode fine in Windows but are not on the list, so they show that nothing else is tried.
    [Fact]
    public void Only_jpeg_png_bmp_and_gif_are_hashed()
    {
        Assert.NotNull(DHash.Compute(As(new System.Windows.Media.Imaging.BmpBitmapEncoder())));
        Assert.NotNull(DHash.Compute(As(new System.Windows.Media.Imaging.GifBitmapEncoder())));
        Assert.Null(DHash.Compute(As(new System.Windows.Media.Imaging.TiffBitmapEncoder())));
        Assert.Null(DHash.Compute(As(new System.Windows.Media.Imaging.WmpBitmapEncoder())));
    }

    [Theory]
    [InlineData("avif", new byte[] { 0, 0, 0, 0x1C, (byte)'f', (byte)'t', (byte)'y', (byte)'p', (byte)'a', (byte)'v', (byte)'i', (byte)'f', 0, 0, 0, 0 })]
    [InlineData("heic", new byte[] { 0, 0, 0, 0x18, (byte)'f', (byte)'t', (byte)'y', (byte)'p', (byte)'h', (byte)'e', (byte)'i', (byte)'c', 0, 0, 0, 0 })]
    [InlineData("webp", new byte[] { (byte)'R', (byte)'I', (byte)'F', (byte)'F', 8, 0, 0, 0, (byte)'W', (byte)'E', (byte)'B', (byte)'P', (byte)'V', (byte)'P', (byte)'8', (byte)' ' })]
    [InlineData("tiff", new byte[] { (byte)'I', (byte)'I', 42, 0, 8, 0, 0, 0, 0, 0, 0, 0 })]
    [InlineData("svg", new byte[] { (byte)'<', (byte)'s', (byte)'v', (byte)'g', (byte)' ', (byte)'/', (byte)'>' })]
    [InlineData("random", new byte[] { 0x13, 0x37, 0xC0, 0xDE, 0, 1, 2, 3, 4, 5, 6, 7 })]
    [InlineData("almost jpeg", new byte[] { 0xFF, 0xD8, 0x00 })]
    public void Other_formats_never_reach_a_decoder(string name, byte[] bytes)
    {
        int calls = 0;
        Assert.Null(DHash.Compute(bytes, (_, _) => { calls++; return 1UL; }));
        Assert.True(calls == 0, name);
    }

    [Fact]
    public void Each_allowed_format_is_decoded_with_its_built_in_codec()
    {
        var seen = new List<Guid>();
        ulong? Spy(Guid codec, byte[] _) { seen.Add(codec); return 1UL; }
        DHash.Compute(Original, Spy);                                                      // PNG
        DHash.Compute(Resaved, Spy);                                                       // JPEG
        DHash.Compute(As(new System.Windows.Media.Imaging.BmpBitmapEncoder()), Spy);
        DHash.Compute(As(new System.Windows.Media.Imaging.GifBitmapEncoder()), Spy);
        Assert.Equal([Windows.Graphics.Imaging.BitmapDecoder.PngDecoderId, Windows.Graphics.Imaging.BitmapDecoder.JpegDecoderId,
            Windows.Graphics.Imaging.BitmapDecoder.BmpDecoderId, Windows.Graphics.Imaging.BitmapDecoder.GifDecoderId], seen);
    }

    [Fact]
    public void Group_joins_near_duplicates_transitively()
    {
        var groups = DHash.Group(
        [
            ("a", 0x0000_0000_0000_0000UL),
            ("b", 0x0000_0000_0000_00FFUL),   // 8 from a
            ("c", 0x0000_0000_0000_FFFFUL),   // 8 from b, 16 from a -> joined through b
            ("d", 0xFFFF_FFFF_FFFF_0000UL),   // far from everything
            ("e", 0xFFFF_FFFF_FFFF_0001UL),   // 1 from d
            ("f", 0x5555_5555_5555_5555UL),   // alone
        ]);

        Assert.Equal(0, groups["a"]);
        Assert.Equal(0, groups["b"]);
        Assert.Equal(0, groups["c"]);
        Assert.Equal(1, groups["d"]);
        Assert.Equal(1, groups["e"]);
        Assert.Equal(2, groups["f"]);
    }

    [Fact]
    public void Large_sets_use_banding_and_match_brute_force()
    {
        var rng = new Random(42);
        var items = new List<(string, ulong)>();
        for (int i = 0; i < 20_500; i++)
        {
            ulong h = (ulong)rng.NextInt64();
            items.Add(($"k{i}", h));
            if (i % 100 == 0) items.Add(($"k{i}-near", h ^ (1UL << rng.Next(64)) ^ (1UL << rng.Next(64))));
        }
        var groups = DHash.Group(items);

        for (int i = 0; i < 20_500; i += 100)
            Assert.Equal(groups[$"k{i}"], groups[$"k{i}-near"]);
        // Random 64-bit hashes are almost never within 10 bits, so nearly every other key is alone.
        Assert.True(groups.Values.Distinct().Count() > 20_000);
    }
}
