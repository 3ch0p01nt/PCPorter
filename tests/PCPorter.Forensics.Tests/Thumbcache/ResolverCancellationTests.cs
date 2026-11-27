using System.Diagnostics;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.Tests.Thumbcache;

/// <summary>
/// Cancel must stop path matching quickly. It used to be ignored: the shell walk ran to its 3-minute budget, so pressing
/// Cancel on "Images viewed" took about 3 minutes to take effect.
/// </summary>
public class ResolverCancellationTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-cancel").FullName;
    public void Dispose() => Directory.Delete(_root, true);

    string ManyFiles(int count)
    {
        for (int i = 0; i < count; i++)
        {
            var dir = Path.Combine(_root, "d" + (i / 100));
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, $"p{i}.jpg"), [0xFF, 0xD8, 0xFF]);
        }
        return _root;
    }

    [Fact]
    public void Shell_walk_stops_soon_after_cancel()
    {
        var resolver = new ShellCacheIdResolver([ManyFiles(3000)], timeBudget: TimeSpan.FromMinutes(3));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var sw = Stopwatch.StartNew();
        Assert.ThrowsAny<OperationCanceledException>(() => resolver.Resolve([0xDEADBEEFUL], cts.Token));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Shell_walk_with_a_cancelled_token_does_not_start()
    {
        var resolver = new ShellCacheIdResolver([ManyFiles(10)]);
        Assert.ThrowsAny<OperationCanceledException>(() => resolver.Resolve([1UL], new CancellationToken(canceled: true)));
    }

    sealed class Recording(Action? onResolve = null) : IThumbnailPathResolver
    {
        public int Calls;
        public CancellationToken Seen;
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids) => Resolve(ids, default);
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids, CancellationToken ct)
        {
            Calls++; Seen = ct; onResolve?.Invoke();
            return new Dictionary<ulong, string>();
        }
    }

    [Fact]
    public void Chain_passes_the_token_and_stops_between_resolvers()
    {
        using var cts = new CancellationTokenSource();
        var first = new Recording(() => cts.Cancel());
        var second = new Recording();
        Assert.ThrowsAny<OperationCanceledException>(() => new ChainedPathResolver(first, second).Resolve([1UL], cts.Token));
        Assert.Equal(cts.Token, first.Seen);
        Assert.Equal(0, second.Calls);
    }

    [Fact]
    public void Collector_hands_its_token_to_the_resolver()
    {
        var explorer = Path.Combine(_root, "Users", "bob", "AppData", "Local", "Microsoft", "Windows", "Explorer");
        Directory.CreateDirectory(explorer);
        var resolver = new Recording();
        using var cts = new CancellationTokenSource();
        new ThumbnailCollector(resolver).Collect([new ThumbnailSource("bob", explorer)], Path.Combine(_root, "out"), ct: cts.Token);
        Assert.Equal(1, resolver.Calls);
        Assert.Equal(cts.Token, resolver.Seen);
    }
}
