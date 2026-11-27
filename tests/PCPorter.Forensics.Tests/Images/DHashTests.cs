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
