using PCPorter.Forensics.Thumbcache;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.Thumbcache;

public class ShellCacheIdResolverTests(ITestOutputHelper output)
{
    [Fact]
    public void Empty_request_does_nothing() =>
        Assert.Empty(new ShellCacheIdResolver([Path.GetTempPath()]).Resolve([]));

    [Fact]
    public void Missing_root_is_harmless() =>
        Assert.Empty(new ShellCacheIdResolver([@"Q:\definitely-not-here"]).Resolve([1UL]));

    /// <summary>
    /// Proves the shell's System.ThumbnailCacheId equals the id stored in this PC's thumbnail caches:
    /// reads this user's cache ids, walks the profile, counts matches. Prints counts only (no paths).
    /// </summary>
    [LocalThumbcacheFact]
    [Trait("Category", "Live")]
    public void Shell_ids_match_this_pcs_thumbnail_cache_ids()
    {
        var ids = new HashSet<ulong>();
        foreach (var f in Directory.EnumerateFiles(LocalThumbcacheFactAttribute.Folder, "thumbcache_*.db"))
        {
            if (f.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) continue;
            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length == 0) continue;
            foreach (var e in ThumbcacheParser.Parse(fs, Path.GetFileName(f)).Entries) ids.Add(e.CacheId);
        }
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var resolver = new ShellCacheIdResolver([profile], maxItems: 200_000, timeBudget: TimeSpan.FromMinutes(4));
        var map = resolver.Resolve(ids);
        output.WriteLine($"cache ids {ids.Count}, matched via shell {map.Count}, notes {resolver.Notes.Count}");
        Assert.NotEmpty(map);
        Assert.All(map, kv => Assert.True(File.Exists(kv.Value) || Directory.Exists(kv.Value)));
    }
}
