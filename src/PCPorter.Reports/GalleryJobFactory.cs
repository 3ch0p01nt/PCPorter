using PCPorter.Core.Snapshots;
using PCPorter.Forensics.BrowserCache;
using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Forensics.SearchIndex;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Reports;

/// <summary>Builds the full "images viewed" job for this running PC from a few user choices.</summary>
public static class GalleryJobFactory
{
    public sealed record Settings(bool AllUsers = false, bool Web = true, bool FullIndex = false, bool RestorePoints = true, bool ShellMatch = true);

    const string SearchFolder = @"C:\ProgramData\Microsoft\Search";

    public static ThumbnailJobOptions Options(Settings s, bool elevated, IProgress<string>? progress = null)
    {
        var extra = new List<IImageEvidenceSource> { new ScreenshotSource(), new RecentImageOpensSource() };
        if (s.Web) { extra.Add(new ChromiumCacheSource()); extra.Add(new FirefoxCacheSource()); }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var notes = WindowsRecallDetector.DetectAll(profile).ToList();
        if (!elevated) notes.Add("PCPorter is not running as administrator: the Windows Search index and restore points could not be read, so fewer original paths are known.");

        return new ThumbnailJobOptions(
            AllUsers: s.AllUsers,
            ExtraSources: extra,
            DuplicateGrouper: GroupSimilar,
            ExtraNotes: notes,
            ResolverFactory: work => Resolver(s, elevated, work, profile, progress),
            AdditionalSources: s.RestorePoints && elevated ? RestorePointSources : null);
    }

    static IThumbnailPathResolver Resolver(Settings s, bool elevated, string work, string profile, IProgress<string>? progress)
    {
        var chain = new List<IThumbnailPathResolver>();
        bool win11 = File.Exists(SearchIndexPathResolver.DefaultWindows11Path);
        bool win10 = !win11 && File.Exists(Path.Combine(SearchFolder, "Data", "Applications", "Windows", "Windows.edb"));
        if (win11) chain.Add(new SearchIndexPathResolver(SearchIndexPathResolver.DefaultWindows11Path, progress, s.FullIndex ? work : null));
        else if (win10 && elevated) chain.Add(new SnapshotIndexResolver(work, progress));   // Search keeps Windows.edb locked
        else chain.Add(SearchIndexResolverFactory.ForPc(SearchFolder, work, progress));
        if (s.ShellMatch) chain.Add(ShellCacheIdResolver.ForProfile(profile));
        return new ChainedPathResolver([.. chain]);
    }

    /// <summary>Windows 10: copy the locked index out of a temporary shadow copy (created and removed by PCPorter).</summary>
    /// <remarks>
    /// The paths found are kept even when only removing the shadow copy fails (that gets its own note), and a Cancel
    /// is never turned into a note.
    /// </remarks>
    public sealed class SnapshotIndexResolver(string work, IProgress<string>? progress,
        ISnapshotProvider? provider = null, Func<string, IThumbnailPathResolver>? innerFor = null) : IThumbnailPathResolver
    {
        readonly List<string> _notes = [];
        public IReadOnlyList<string> Notes => _notes;
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids) => Resolve(ids, default);

        static bool Expected(Exception e) =>
            e is InvalidOperationException or UnauthorizedAccessException or System.Management.ManagementException or IOException
            && e is not OperationCanceledException;   // ObjectDisposed/OperationCanceled derive from InvalidOperationException

        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> ids, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            ISnapshot? snap = null;
            IReadOnlyDictionary<ulong, string> map = new Dictionary<ulong, string>();
            try
            {
                progress?.Report("Taking a temporary shadow copy to read the Windows 10 search index");
                snap = (provider ?? new VssSnapshotProvider()).Create(@"C:\");
                var inner = innerFor?.Invoke(snap.Map(SearchFolder)) ?? SearchIndexResolverFactory.ForPc(snap.Map(SearchFolder), work, progress);
                map = inner.Resolve(ids, ct);
                _notes.AddRange(inner.Notes);
            }
            catch (Exception e) when (Expected(e))
            {
                _notes.Add("The Windows 10 search index could not be read (" + e.Message + "). Original file paths are shown as unknown.");
            }
            finally
            {
                // Runs on Cancel too; a failure here must neither hide the Cancel nor throw away the paths found.
                try { snap?.Dispose(); }
                catch (Exception e) when (Expected(e))
                {
                    _notes.Add("The temporary shadow copy could not be removed (" + e.Message + "). The paths found were kept. PCPorter removes it the next time it takes a shadow copy.");
                }
            }
            return map;
        }
    }

    /// <summary>Thumbnail caches inside existing restore points (read-only; PCPorter never creates restore points for this).</summary>
    static IReadOnlyList<ThumbnailSource> RestorePointSources(IReadOnlyList<ThumbnailSource> live)
    {
        var list = new List<ThumbnailSource>();
        foreach (var (_, device, created) in VssSnapshotProvider.ListExisting(@"C:\"))
            foreach (var src in live)
            {
                if (!src.ExplorerFolder.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase)) continue;
                var mapped = VssSnapshotProvider.MapPath(device, @"C:\", src.ExplorerFolder);
                if (Directory.Exists(mapped)) list.Add(new ThumbnailSource(src.User, mapped, RestorePoint: created));
            }
        return list;
    }

    /// <summary>Groups bigger than this are generic look-alikes (folder art, UI images), not real duplicates.</summary>
    const int MaxGroupSize = 40;

    /// <summary>
    /// Groups visually similar pictures (64-bit difference hash, distance &lt;= 10). Folder previews and program icons are
    /// left out (they all look alike), and very large groups are dropped as noise.
    /// </summary>
    public static IReadOnlyDictionary<string, int> GroupSimilar(IReadOnlyList<GalleryItem> items, string imagesFolder, CancellationToken ct = default)
    {
        var hashes = new List<(string, ulong)>();
        var byFile = new Dictionary<string, ulong?>();
        foreach (var i in items)
        {
            ct.ThrowIfCancellationRequested();
            if (i.Best is not { } best || i.Kind == "icon" || IsFolder(i.OriginalPath)) continue;
            if (!byFile.TryGetValue(best.File, out var h))
            {
                try { h = DHash.Compute(File.ReadAllBytes(Path.Combine(imagesFolder, best.File))); }
                catch (IOException) { h = null; }
                byFile[best.File] = h;
            }
            if (h is { } v) hashes.Add((i.Id, v));
        }
        var groups = DHash.Group(hashes);
        var sizes = groups.Values.GroupBy(g => g).ToDictionary(g => g.Key, g => g.Count());
        return groups.Where(kv => sizes[kv.Value] is > 1 and <= MaxGroupSize).ToDictionary(kv => kv.Key, kv => kv.Value);
    }

    /// <summary>A path with no extension that is (or was) a folder: Explorer's folder preview, not a picture.</summary>
    static bool IsFolder(string? path) =>
        path is not null && (Directory.Exists(path) || string.IsNullOrEmpty(Path.GetExtension(path)));
}
