using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Tests.Thumbcache;

public class ThumbcacheParserTests
{
    static ThumbcacheFile Parse(byte[] file) => ThumbcacheParser.Parse(file, "thumbcache_96.db");
    static IEnumerable<ThumbcacheEntry> Images(ThumbcacheFile f) => f.Entries.Where(e => e.HasImage);

    [Fact]
    public void Parses_png_and_jpeg_entries_with_ids_and_sizes()
    {
        var file = Parse(new ThumbcacheBuilder()
            .Entry(0x2e816de75f25cd34, ThumbcacheBuilder.Png, 256, 192)
            .Entry(0x0000000000000abc, ThumbcacheBuilder.Jpeg, 96, 64)
            .Build());

        Assert.Equal(0x20, file.Version);
        Assert.True(file.VersionKnown);
        Assert.Equal(2, file.Entries.Count);
        var png = file.Entries[0];
        Assert.Equal(0x2e816de75f25cd34UL, png.CacheId);
        Assert.Equal("2e816de75f25cd34", png.Identifier);
        Assert.Equal((256, 192), (png.Width, png.Height));
        Assert.Equal(ImageFormat.Png, png.Format);
        Assert.Equal(ImageFormat.Jpeg, file.Entries[1].Format);
        Assert.False(png.FoundInFreeSpace);
    }

    [Fact]
    public void Image_bytes_are_returned_exactly_from_memory_and_stream()
    {
        var bytes = new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Jpeg).Build();
        var file = Parse(bytes);
        Assert.Equal(ThumbcacheBuilder.Jpeg, ThumbcacheParser.ImageBytes(bytes, file.Entries[0]).ToArray());
        using var ms = new MemoryStream(bytes);
        Assert.Equal(ThumbcacheBuilder.Jpeg, ThumbcacheParser.ReadImage(ms, ThumbcacheParser.Parse(ms, "x").Entries[0]));
    }

    [Fact]
    public void Entries_without_image_data_are_kept_with_their_cache_id()
    {
        var file = Parse(new ThumbcacheBuilder()
            .Entry(0x77, [], identifier: "0000000000000077")
            .Entry(2, ThumbcacheBuilder.Png)
            .Build());
        Assert.Equal(2, file.Entries.Count);
        var empty = file.Entries[0];
        Assert.False(empty.HasImage);
        Assert.Equal(0x77UL, empty.CacheId);
        Assert.Equal(1, file.EmptyEntries);
        Assert.Equal(1, file.ImageEntries);
    }

    [Fact]
    public void Free_space_record_does_not_hide_entries_behind_it()
    {
        // Windows 11 writes one id-0 record whose size covers the rest of the file (verified on a real PC).
        var bytes = new ThumbcacheBuilder()
            .Entry(1, ThumbcacheBuilder.Png)
            .FreeSpaceRecord(coverBytes: 4096)
            .Garbage(16, 0)
            .Entry(2, ThumbcacheBuilder.Jpeg)       // an older entry left inside free space
            .Garbage(1000, 0)
            .Build();
        var file = Parse(bytes);
        Assert.Equal([1UL, 2UL], Images(file).Select(e => e.CacheId));
        Assert.False(file.Entries[0].FoundInFreeSpace);
        Assert.True(file.Entries[1].FoundInFreeSpace);
    }

    [Fact]
    public void Garbage_between_entries_is_skipped_and_the_next_entry_is_marked()
    {
        var file = Parse(new ThumbcacheBuilder()
            .Entry(1, ThumbcacheBuilder.Png)
            .Garbage(37)
            .Entry(2, ThumbcacheBuilder.Jpeg)
            .Build());
        Assert.Equal(2, file.Entries.Count);
        Assert.False(file.Entries[0].FoundInFreeSpace);
        Assert.True(file.Entries[1].FoundInFreeSpace);
    }

    [Fact]
    public void Scanned_entries_must_look_real()
    {
        // A "CMMM" inside garbage with nonsense fields must not become an entry.
        var fake = new byte[80];
        "CMMM"u8.CopyTo(fake);
        BitConverter.GetBytes(80u).CopyTo(fake, 4);
        BitConverter.GetBytes(0xDEADUL).CopyTo(fake, 8);
        BitConverter.GetBytes(8u).CopyTo(fake, 16);   // identifier "zzzz" (not hex/path)
        BitConverter.GetBytes(4u).CopyTo(fake, 24);   // 4 bytes of data, not an image
        System.Text.Encoding.Unicode.GetBytes("zzzz").CopyTo(fake, 56);
        var bytes = new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Garbage(5).Build().Concat(fake).ToArray();
        Assert.Equal([1UL], Parse(bytes).Entries.Select(e => e.CacheId));
    }

    [Fact]
    public void Entries_after_first_free_offset_are_marked()
    {
        var file = Parse(new ThumbcacheBuilder()
            .Entry(1, ThumbcacheBuilder.Png)
            .FreeSpaceStartsHere()
            .Entry(2, ThumbcacheBuilder.Jpeg)
            .Build());
        Assert.False(file.Entries[0].FoundInFreeSpace);
        Assert.True(file.Entries[1].FoundInFreeSpace);
    }

    [Fact]
    public void Truncated_last_entry_gives_a_warning_not_an_exception()
    {
        var bytes = new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Entry(2, ThumbcacheBuilder.Jpeg).Build();
        var file = Parse(bytes[..^8]);
        Assert.Single(file.Entries);
        Assert.NotEmpty(file.Warnings);
    }

    [Theory]
    [InlineData(0x14u)]   // Vista
    [InlineData(0x15u)]   // Windows 7
    [InlineData(0x1Au)]   // Windows 8 preview
    [InlineData(0x1Cu)]   // Windows 8 preview (28-byte header)
    [InlineData(0x1Eu)]   // Windows 8.0
    [InlineData(0x1Fu)]   // Windows 8.1
    [InlineData(0x20u)]   // Windows 10/11
    public void Every_known_version_layout_parses(uint version)
    {
        var file = Parse(new ThumbcacheBuilder(version).Entry(7, ThumbcacheBuilder.Jpeg).Entry(8, ThumbcacheBuilder.Png).Build());
        Assert.Equal((int)version, file.Version);
        Assert.True(file.VersionKnown);
        Assert.Equal([7UL, 8UL], file.Entries.Select(e => e.CacheId));
        Assert.Equal([ImageFormat.Jpeg, ImageFormat.Png], file.Entries.Select(e => e.Format));
        Assert.Empty(file.Warnings);
    }

    [Fact]
    public void Unknown_version_warns()
    {
        var file = Parse(new ThumbcacheBuilder(0x21).Entry(1, ThumbcacheBuilder.Png).Build());
        Assert.False(file.VersionKnown);
        Assert.Contains(file.Warnings, w => w.Contains("unknown cache format version"));
    }

    [Fact]
    public void Wrong_signature_throws()
    {
        var bytes = new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Build();
        bytes[0] = (byte)'X';
        Assert.Throws<InvalidDataException>(() => Parse(bytes));
    }

    [Fact]
    public void Empty_or_header_only_file()
    {
        Assert.Throws<InvalidDataException>(() => Parse([]));
        Assert.Empty(Parse(new ThumbcacheBuilder().Build()).Entries);
    }

    [Fact]
    public void Random_damage_never_throws()
    {
        var rnd = new Random(42);
        var good = new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Entry(2, ThumbcacheBuilder.Jpeg).Entry(3, ThumbcacheBuilder.Png).Build();
        for (int i = 0; i < 500; i++)
        {
            var bytes = good.Concat(Enumerable.Range(0, rnd.Next(0, 300)).Select(_ => (byte)rnd.Next(256))).ToArray();
            for (int k = rnd.Next(1, 12); k > 0; k--) bytes[rnd.Next(24, bytes.Length)] = (byte)rnd.Next(256);   // damage headers too
            if (rnd.Next(4) == 0) bytes = bytes[..rnd.Next(24, bytes.Length)];                                // random truncation
            _ = Parse(bytes);
        }
    }
}
