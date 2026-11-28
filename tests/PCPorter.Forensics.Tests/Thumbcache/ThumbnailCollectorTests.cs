using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Tests.Thumbcache;

public class ThumbnailCollectorTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-thumbs").FullName;
    public void Dispose() => Directory.Delete(_root, true);

    sealed class MapResolver(Dictionary<ulong, string> map) : IThumbnailPathResolver
    {
        public IReadOnlyCollection<ulong>? Asked { get; private set; }
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids)
        {
            Asked = ids;
            return ids.Where(map.ContainsKey).ToDictionary(id => id, id => map[id]);
        }
    }

    string Explorer(string user, params (string Name, byte[] Bytes)[] files)
    {
        var dir = Path.Combine(_root, "Users", user, "AppData", "Local", "Microsoft", "Windows", "Explorer");
        Directory.CreateDirectory(dir);
        foreach (var (name, bytes) in files) File.WriteAllBytes(Path.Combine(dir, name), bytes);
        return dir;
    }

    GalleryScanResult Collect(IThumbnailPathResolver resolver, params ThumbnailSource[] sources) =>
        new ThumbnailCollector(resolver).Collect(sources, Path.Combine(_root, "out"));

    [Fact]
    public void Groups_sizes_by_cache_id_and_picks_the_largest_as_best()
    {
        var dir = Explorer("bob",
            ("thumbcache_96.db", new ThumbcacheBuilder().Entry(0xAA, ThumbcacheBuilder.Png, 96, 72).Build()),
            ("thumbcache_256.db", new ThumbcacheBuilder().Entry(0xAA, ThumbcacheBuilder.Jpeg, 256, 192).Build()),
            ("thumbcache_idx.db", [1, 2, 3]));
        var result = Collect(new NoPathResolver(), new ThumbnailSource("bob", dir));

        var item = Assert.Single(result.Items);
        Assert.Equal("00000000000000aa", item.CacheId);
        Assert.Equal(2, item.Images.Count);
        Assert.Equal("256", item.Best!.SizeClass);
        Assert.Equal(OriginalStatus.Unknown, item.Status);
        Assert.Equal(ThumbcacheBuilder.Jpeg, File.ReadAllBytes(Path.Combine(_root, "out", item.Best.File)));
    }

    [Fact]
    public void Identical_images_are_stored_once()
    {
        var dir = Explorer("bob",
            ("thumbcache_96.db", new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Entry(2, ThumbcacheBuilder.Png).Build()));
        var result = Collect(new NoPathResolver(), new ThumbnailSource("bob", dir));
        Assert.Equal(2, result.Items.Count);
        Assert.Single(Directory.GetFiles(Path.Combine(_root, "out")));
        Assert.Equal(result.Items[0].Best!.File, result.Items[1].Best!.File);
    }

    [Fact]
    public void Entries_without_pictures_become_items_with_a_note()
    {
        var dir = Explorer("bob", ("thumbcache_256.db", new ThumbcacheBuilder().Entry(0x55, []).Build()));
        var resolver = new MapResolver(new() { [0x55] = Path.Combine(_root, "Pics", "gone.jpg") });
        var item = Assert.Single(Collect(resolver, new ThumbnailSource("bob", dir)).Items);
        Assert.False(item.HasImage);
        Assert.NotNull(item.Note);
        Assert.Equal(Path.Combine(_root, "Pics", "gone.jpg"), item.OriginalPath);
    }

    [Fact]
    public void Live_copy_wins_over_free_space_copy_and_item_is_live()
    {
        var dir = Explorer("bob", ("thumbcache_96.db", new ThumbcacheBuilder()
            .Entry(9, ThumbcacheBuilder.Png)
            .FreeSpaceStartsHere()
            .Entry(9, ThumbcacheBuilder.Jpeg)
            .Build()));
        var item = Assert.Single(Collect(new NoPathResolver(), new ThumbnailSource("bob", dir)).Items);
        Assert.False(item.FoundInFreeSpace);
        Assert.Equal(ImageFormatPng(), item.Best!.Format);
        static PCPorter.Forensics.Thumbcache.ImageFormat ImageFormatPng() => PCPorter.Forensics.Thumbcache.ImageFormat.Png;
    }

    [Fact]
    public void Statuses_use_real_folders()
    {
        var pics = Directory.CreateDirectory(Path.Combine(_root, "Pics")).FullName;
        File.WriteAllBytes(Path.Combine(pics, "kept.jpg"), [1]);
        var album = Directory.CreateDirectory(Path.Combine(pics, "Holiday")).FullName;
        var dir = Explorer("bob", ("thumbcache_96.db", new ThumbcacheBuilder()
            .Entry(1, ThumbcacheBuilder.Png).Entry(2, ThumbcacheBuilder.Png).Entry(3, ThumbcacheBuilder.Png).Entry(4, ThumbcacheBuilder.Png).Build()));
        var resolver = new MapResolver(new()
        {
            [1] = Path.Combine(pics, "kept.jpg"),
            [2] = Path.Combine(pics, "gone.jpg"),
            [3] = album,                                            // folder thumbnail
            [4] = @"Q:\NoSuchDrive\x.jpg",                          // drive not present
        });
        var byId = Collect(resolver, new ThumbnailSource("bob", dir)).Items.ToDictionary(i => i.CacheId!);
        Assert.Equal(OriginalStatus.Exists, byId["0000000000000001"].Status);
        Assert.Equal(OriginalStatus.Deleted, byId["0000000000000002"].Status);
        Assert.Equal(OriginalStatus.Exists, byId["0000000000000003"].Status);
        Assert.Equal(OriginalStatus.Unreachable, byId["0000000000000004"].Status);
        Assert.Equal("Medium", byId["0000000000000001"].Dates!.Confidence);
        Assert.Equal("Low", byId["0000000000000002"].Dates!.Confidence);
    }

    [Fact]
    public void Restore_point_copies_merge_into_the_live_item()
    {
        var live = Explorer("bob", ("thumbcache_96.db", new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Png).Build()));
        var rpDir = Path.Combine(_root, "rp", "Explorer");
        Directory.CreateDirectory(rpDir);
        File.WriteAllBytes(Path.Combine(rpDir, "thumbcache_96.db"),
            new ThumbcacheBuilder().Entry(1, ThumbcacheBuilder.Jpeg).Entry(2, ThumbcacheBuilder.Png).Build());
        var created = new DateTimeOffset(2026, 3, 10, 9, 0, 0, TimeSpan.Zero);

        var result = Collect(new NoPathResolver(), new ThumbnailSource("bob", live), new ThumbnailSource("bob", rpDir, created));

        Assert.Equal(2, result.Items.Count);                                     // not 3: the copy of #1 is merged
        Assert.All(result.Items, i => Assert.Equal("bob", i.User));
        var both = result.Items.Single(i => i.CacheId == "0000000000000001");
        Assert.False(both.OnlyInRestorePoints);
        Assert.Equal([created], both.RestorePoints!);
        Assert.Equal(2, both.Images.Count);
        Assert.Null(both.Best!.RestorePoint);                                    // the live copy is shown first
        var old = result.Items.Single(i => i.CacheId == "0000000000000002");
        Assert.True(old.OnlyInRestorePoints);
        Assert.Contains("only in a restore point", old.Note);
        Assert.Equal(2, result.Summary.Thumbnails);
        Assert.Equal(1, result.Summary.OnlyInRestorePoints);
    }

    [Fact]
    public void Icons_are_separate_and_never_resolved()
    {
        var dir = Explorer("bob",
            ("thumbcache_48.db", new ThumbcacheBuilder().Entry(5, ThumbcacheBuilder.Png).Build()),
            ("iconcache_48.db", new ThumbcacheBuilder().Entry(5, ThumbcacheBuilder.Jpeg).Build()));
        var resolver = new MapResolver(new() { [5] = @"C:\x.jpg" });
        var result = Collect(resolver, new ThumbnailSource("bob", dir));
        Assert.Equal([5UL], resolver.Asked);
        Assert.Equal(2, result.Items.Count);
        Assert.Null(result.Items.Single(i => i.Kind == "icon").OriginalPath);
    }

    [Fact]
    public void Unreadable_or_corrupt_files_become_warnings()
    {
        var dir = Explorer("bob", ("thumbcache_96.db", "not a cache file at all......."u8.ToArray()));
        var result = Collect(new NoPathResolver(), new ThumbnailSource("bob", dir), new ThumbnailSource("ghost", Path.Combine(_root, "missing")));
        Assert.Empty(result.Items);
        Assert.Equal(2, result.Warnings.Count);
    }

    [Fact]
    public void Live_sources_default_to_the_current_user_only()
    {
        Explorer("alice", ("thumbcache_96.db", []));
        Explorer("bob", ("thumbcache_96.db", []));
        Directory.CreateDirectory(Path.Combine(_root, "Users", "Public"));
        var users = Path.Combine(_root, "Users");
        var mine = ThumbnailCollector.LiveSources(currentProfile: Path.Combine(users, "bob"));
        Assert.Equal("bob", Assert.Single(mine).User);
        var all = ThumbnailCollector.LiveSources(allUsers: true, usersRoot: users, currentProfile: Path.Combine(users, "bob"));
        Assert.Equal(["alice", "bob"], all.Select(s => s.User).Order());
    }

    [Fact]
    public void Chained_resolver_only_asks_later_resolvers_for_missing_ids()
    {
        var first = new MapResolver(new() { [1] = "a" });
        var second = new MapResolver(new() { [2] = "b" });
        var map = new ChainedPathResolver(first, second).Resolve([1UL, 2UL, 3UL]);
        Assert.Equal(2, map.Count);
        Assert.Equal([2UL, 3UL], second.Asked!.Order());
    }
}
