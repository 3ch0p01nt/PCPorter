using System.Text.RegularExpressions;
using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Thumbcache;

/// <summary>Where one user's Explorer caches live.</summary>
public sealed record ThumbnailSource(string User, string ExplorerFolder);

/// <summary>Maps thumbnail cache ids to original file paths (e.g. via the Windows Search index). Called once with every id.</summary>
public interface IThumbnailPathResolver
{
    IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds);

    /// <summary>Notes for the report (e.g. "search index not readable without admin").</summary>
    IReadOnlyList<string> Notes => [];
}

public sealed class NoPathResolver : IThumbnailPathResolver
{
    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds) => new Dictionary<ulong, string>();
}

/// <summary>Tries several resolvers in order; later ones only see ids the earlier ones could not map.</summary>
public sealed class ChainedPathResolver(params IThumbnailPathResolver[] resolvers) : IThumbnailPathResolver
{
    public IReadOnlyList<string> Notes => resolvers.SelectMany(r => r.Notes).ToList();

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds)
    {
        var result = new Dictionary<ulong, string>();
        IReadOnlyCollection<ulong> remaining = cacheIds;
        foreach (var r in resolvers)
        {
            if (remaining.Count == 0) break;
            foreach (var (id, path) in r.Resolve(remaining)) result.TryAdd(id, path);
            remaining = remaining.Where(id => !result.ContainsKey(id)).ToHashSet();
        }
        return result;
    }
}

/// <summary>
/// Reads every thumbcache/iconcache file for each source (streamed, read-only), stores each distinct image once,
/// groups entries by cache id, and works out original-file status and a "displayed between" window.
/// The scanned PC is never modified.
/// </summary>
public sealed partial class ThumbnailCollector(IThumbnailPathResolver resolver, OriginalLocator? locator = null)
{
    readonly OriginalLocator _locator = locator ?? new OriginalLocator();

    [GeneratedRegex(@"^(?<kind>thumbcache|iconcache)_(?<size>[a-z0-9_]+)\.db$", RegexOptions.IgnoreCase)]
    private static partial Regex CacheFileName();

    sealed record Copy(GalleryImage? Image, string SizeClass, bool FreeSpace, string CacheFile, DateTimeOffset CacheCreated, DateTimeOffset CacheModified);

    public GalleryScanResult Collect(IEnumerable<ThumbnailSource> sources, string imagesFolder,
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var store = new ImageStore(imagesFolder);
        var warnings = new List<string>();
        var summaries = new List<CacheFileSummary>();
        var byKey = new Dictionary<(string User, string Kind, ulong Id), Dictionary<string, Copy>>();
        var indexed = new Dictionary<string, HashSet<ulong>>();   // per user: ids listed in thumbcache_idx.db

        foreach (var source in sources)
        {
            ct.ThrowIfCancellationRequested();
            if (IsReparsePoint(source.ExplorerFolder))
            {
                warnings.Add($"Skipped the thumbnail folder for {source.User}: it is a link to another location.");
                continue;
            }
            List<string> files;
            try { files = Directory.EnumerateFiles(source.ExplorerFolder, "*.db").ToList(); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                warnings.Add($"Could not open the thumbnail folder for {source.User}: {ex.Message}");
                continue;
            }

            if (ThumbcacheIndexParser.ReadIds(Path.Combine(source.ExplorerFolder, "thumbcache_idx.db")) is { } idxIds)
                indexed[source.User] = idxIds;

            foreach (var path in files)
            {
                ct.ThrowIfCancellationRequested();
                var m = CacheFileName().Match(Path.GetFileName(path));
                if (!m.Success || m.Groups["size"].Value.Equals("idx", StringComparison.OrdinalIgnoreCase)) continue;
                var kind = m.Groups["kind"].Value.Equals("thumbcache", StringComparison.OrdinalIgnoreCase) ? "thumbnail" : "icon";
                var sizeClass = m.Groups["size"].Value.ToLowerInvariant();
                progress?.Report($"{source.User}: {Path.GetFileName(path)}");

                try
                {
                    // Explorer keeps these open: share read/write/delete so we never block it.
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                        bufferSize: 1 << 20, FileOptions.RandomAccess);
                    if (fs.Length == 0) continue;
                    var info = new FileInfo(path);
                    var parsed = ThumbcacheParser.Parse(fs, Path.GetFileName(path), ct);
                    warnings.AddRange(parsed.Warnings);
                    summaries.Add(new CacheFileSummary(source.User, Path.GetFileName(path), parsed.Version,
                        parsed.ImageEntries, parsed.EmptyEntries, parsed.Warnings.Count));

                    foreach (var e in parsed.Entries)
                    {
                        GalleryImage? image = null;
                        if (e.HasImage)
                        {
                            var bytes = ThumbcacheParser.ReadImage(fs, e);
                            image = new GalleryImage(sizeClass, e.Width, e.Height, store.Save(bytes, e.Format), e.Format, e.FoundInFreeSpace);
                        }
                        var key = (source.User, kind, e.CacheId);
                        if (!byKey.TryGetValue(key, out var copies)) byKey[key] = copies = [];
                        var copy = new Copy(image, sizeClass, e.FoundInFreeSpace, Path.GetFileName(path), info.CreationTimeUtc, info.LastWriteTimeUtc);
                        // One copy per size class; prefer the live copy, then the one with an image.
                        if (!copies.TryGetValue(sizeClass, out var existing) || Better(copy, existing)) copies[sizeClass] = copy;
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidDataException)
                {
                    warnings.Add($"Could not read {Path.GetFileName(path)} for {source.User}: {ex.Message}");
                }
            }
        }

        progress?.Report("Looking up original file paths");
        var paths = resolver.Resolve(byKey.Keys.Where(k => k.Kind == "thumbnail").Select(k => k.Id).ToHashSet());

        progress?.Report("Checking which originals still exist");
        var items = new List<GalleryItem>(byKey.Count);
        foreach (var ((user, kind, id), copies) in byKey)
        {
            ct.ThrowIfCancellationRequested();
            var images = copies.Values.Where(c => c.Image is not null).Select(c => c.Image!)
                .OrderByDescending(i => (long)i.Width * i.Height).ToList();
            var original = kind == "thumbnail" ? paths.GetValueOrDefault(id) : null;
            var status = _locator.Locate(original);
            var dates = DatesFor(original, status, copies.Values);
            bool freeSpace = copies.Values.All(c => c.FreeSpace);
            var notes = new List<string>();
            if (images.Count == 0) notes.Add("Windows showed this item but kept no picture of it.");
            if (kind == "thumbnail" && indexed.TryGetValue(user, out var idx) && !idx.Contains(id))
                notes.Add("Not listed in the cache's own index: an older entry Windows no longer points to.");
            string? note = notes.Count == 0 ? null : string.Join(" ", notes);
            items.Add(new GalleryItem(
                Id: $"{kind[0]}-{user}-{id:x16}", Kind: kind,
                Source: kind == "icon" ? "File Explorer icons" : "File Explorer thumbnails",
                Evidence: EvidenceLevel.Displayed, User: user, CacheId: $"{id:x16}", OriginalPath: original, Url: null,
                Status: kind == "icon" ? OriginalStatus.Unknown : status, FoundInFreeSpace: freeSpace,
                Best: images.FirstOrDefault(), Images: images, Dates: dates, Note: note));
        }

        items = items.OrderBy(i => i.Kind).ThenBy(i => i.User).ThenBy(i => i.OriginalPath is null)
            .ThenBy(i => i.OriginalPath, StringComparer.OrdinalIgnoreCase).ThenBy(i => i.CacheId).ToList();
        return new GalleryScanResult(items, summaries, warnings, resolver.Notes);
    }

    static bool Better(Copy candidate, Copy existing) =>
        (existing.FreeSpace && !candidate.FreeSpace) ||
        (existing.FreeSpace == candidate.FreeSpace && existing.Image is null && candidate.Image is not null);

    /// <summary>
    /// The thumbnail id changes when the file's data is modified (Microsoft), so a matching thumbnail was made after the
    /// file's last change. Entries are written after their cache file was created and before it was last written.
    /// </summary>
    DateWindow DatesFor(string? original, OriginalStatus status, IEnumerable<Copy> copies)
    {
        var list = copies.ToList();
        var sources = new List<string>();
        DateTimeOffset after = list.Min(c => c.CacheCreated);
        DateTimeOffset before = list.Max(c => c.CacheModified);
        sources.Add($"Thumbnail cache file created {after:u} (the picture was stored after this)");
        sources.Add($"Thumbnail cache file last written {before:u} (the picture was stored before this)");
        string confidence = "Low";
        if (original is not null && status == OriginalStatus.Exists && _locator.Times(original) is { } t)
        {
            sources.Add($"Original last modified {t.ModifiedUtc:u} (this thumbnail was made after that change)");
            if (t.ModifiedUtc > after && t.ModifiedUtc <= before) after = t.ModifiedUtc;
            confidence = "Medium";
        }
        return new DateWindow(after, before, confidence, sources);
    }

    static bool IsReparsePoint(string folder)
    {
        try { return Directory.Exists(folder) && new DirectoryInfo(folder).Attributes.HasFlag(FileAttributes.ReparsePoint); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>
    /// Thumbnail folders to read on this running PC. By default only the person running PCPorter;
    /// <paramref name="allUsers"/> adds every other profile (needs admin, and their consent).
    /// </summary>
    public static IReadOnlyList<ThumbnailSource> LiveSources(bool allUsers = false, string? usersRoot = null, string? currentProfile = null)
    {
        currentProfile ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var list = new List<ThumbnailSource>();
        IEnumerable<string> profiles = allUsers ? SafeDirs(usersRoot ?? Path.GetDirectoryName(currentProfile)!) : [currentProfile];
        foreach (var profile in profiles)
        {
            var folder = Path.Combine(profile, "AppData", "Local", "Microsoft", "Windows", "Explorer");
            if (Directory.Exists(folder)) list.Add(new ThumbnailSource(Path.GetFileName(profile), folder));
        }
        return list;
    }

    static IEnumerable<string> SafeDirs(string root)
    {
        try
        {
            return Directory.EnumerateDirectories(root, "*", new EnumerationOptions
            {
                AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true,
            }).ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return []; }
    }
}
