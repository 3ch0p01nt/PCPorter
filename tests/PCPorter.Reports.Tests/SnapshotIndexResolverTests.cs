using PCPorter.Core.Snapshots;
using PCPorter.Forensics.Thumbcache;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class SnapshotIndexResolverTests
{
    sealed class FakeSnapshot(Exception? onDispose) : ISnapshot
    {
        public bool Disposed { get; private set; }
        public string DeviceRoot => @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99";
        public string Map(string livePath) => DeviceRoot + livePath[2..];
        public void Dispose() { Disposed = true; if (onDispose is not null) throw onDispose; }
    }

    sealed class FakeProvider(FakeSnapshot snap) : ISnapshotProvider
    {
        public ISnapshot Create(string volumeRoot) => snap;
    }

    sealed class Inner(Action<CancellationToken>? during = null) : IThumbnailPathResolver
    {
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids) => Resolve(ids, default);
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids, CancellationToken ct)
        {
            during?.Invoke(ct);
            return ids.ToDictionary(id => id, id => $@"C:\Pics\{id}.jpg");
        }
    }

    [Fact]
    public void Paths_are_kept_when_only_removing_the_shadow_copy_fails()
    {
        var snap = new FakeSnapshot(new InvalidOperationException("delete failed"));
        var r = new GalleryJobFactory.SnapshotIndexResolver("work", null, new FakeProvider(snap), _ => new Inner());
        var map = r.Resolve([1UL, 2UL], default);
        Assert.Equal(2, map.Count);
        Assert.True(snap.Disposed);
        var note = Assert.Single(r.Notes);
        Assert.Contains("temporary shadow copy could not be removed", note);
        Assert.DoesNotContain("could not be read", note);
    }

    [Fact]
    public void Cancel_stays_a_cancel_even_when_removal_also_fails()
    {
        using var cts = new CancellationTokenSource();
        var snap = new FakeSnapshot(new InvalidOperationException("delete failed"));
        var r = new GalleryJobFactory.SnapshotIndexResolver("work", null, new FakeProvider(snap),
            _ => new Inner(ct => { cts.Cancel(); ct.ThrowIfCancellationRequested(); }));
        Assert.ThrowsAny<OperationCanceledException>(() => r.Resolve([1UL], cts.Token));
        Assert.True(snap.Disposed);
        Assert.DoesNotContain(r.Notes, n => n.Contains("could not be read"));
    }
}
