using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Tests.Thumbcache;

public class ThumbcacheIndexParserTests
{
    /// <summary>Synthetic idx in the verified Win11 layout: 4 bytes, "IMMM", version 0x20, records of 72 bytes from offset 72.</summary>
    static byte[] Idx(params ulong[] ids)
    {
        var b = new byte[72 + 72 * (ids.Length + 1)];
        "IMMM"u8.CopyTo(b.AsSpan(4));
        BitConverter.GetBytes(0x20u).CopyTo(b, 8);
        for (int i = 0; i < ids.Length; i++) BitConverter.GetBytes(ids[i]).CopyTo(b, 72 + 72 * i);
        return b;
    }

    [Fact]
    public void Reads_listed_ids_and_skips_empty_slots() =>
        Assert.Equal([1UL, 0xABCUL], ThumbcacheIndexParser.ReadIds(new MemoryStream(Idx(1, 0xABC)))!.Order());

    [Fact]
    public void Unknown_versions_and_garbage_return_null()
    {
        var v = Idx(1); BitConverter.GetBytes(0x15u).CopyTo(v, 8);
        Assert.Null(ThumbcacheIndexParser.ReadIds(new MemoryStream(v)));
        Assert.Null(ThumbcacheIndexParser.ReadIds(new MemoryStream(new byte[200])));
        Assert.Null(ThumbcacheIndexParser.ReadIds(new MemoryStream([1, 2, 3])));
    }

    [LocalThumbcacheFact, Trait("Category", "Live")]
    public void This_pcs_index_lists_almost_every_cached_id()
    {
        var idx = ThumbcacheIndexParser.ReadIds(Path.Combine(LocalThumbcacheFactAttribute.Folder, "thumbcache_idx.db"));
        Assert.NotNull(idx);
        var cached = new HashSet<ulong>();
        foreach (var f in Directory.EnumerateFiles(LocalThumbcacheFactAttribute.Folder, "thumbcache_*.db"))
        {
            if (f.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) continue;
            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length > 0) foreach (var e in ThumbcacheParser.Parse(fs, f).Entries) cached.Add(e.CacheId);
        }
        Assert.True(cached.Count(idx!.Contains) >= cached.Count * 0.9, "idx should list at least 90% of cached ids");
    }
}
