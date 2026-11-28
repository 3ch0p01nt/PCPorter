using System.Text.RegularExpressions;
using PCPorter.Collectors.Sources;
using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Thumbcache;

/// <summary>
/// Where one user's Explorer caches live. <paramref name="RestorePoint"/> is set for a copy of that folder inside an
/// existing restore point (its creation time): its entries are merged into the same user's live items.
/// </summary>
public sealed record ThumbnailSource(string User, string ExplorerFolder, DateTimeOffset? RestorePoint = null);

/// <summary>Maps thumbnail cache ids to original file paths (e.g. via the Windows Search index). Called once with every id.</summary>
public interface IThumbnailPathResolver
{
    IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds);

    /// <summary>
    /// Same, stopping with <see cref="OperationCanceledException"/> soon after <paramref name="ct"/> is cancelled.
    /// Resolvers that can run long (file walks, index reads) override this; the default ignores the token.
    /// </summary>
    IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds, CancellationToken ct) => Resolve(cacheIds);

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

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds) => Resolve(cacheIds, default);

    public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds, CancellationToken ct)
    {
        var result = new Dictionary<ulong, string>();
        IReadOnlyCollection<ulong> remaining = cacheIds;
        foreach (var r in resolvers)
        {
            ct.ThrowIfCancellationRequested();
            if (remaining.Count == 0) break;
            foreach (var (id, path) in r.Resolve(remaining, ct)) result.TryAdd(id, path);
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

    sealed record Copy(GalleryImage? Image, string SizeClass, bool FreeSpace, string CacheFile, DateTimeOffset CacheCreated, DateTimeOffset CacheModified, DateTimeOffset? RestorePoint);

    public GalleryScanResult Collect(IEnumerable<ThumbnailSource> sources, string imagesFolder,
        IProgress<string>? progress = null, CancellationToken ct = default) =>
        Collect(sources, new ImageStore(imagesFolder), progress, ct);

    /// <summary>Same, saving pictures into <paramref name="store"/> (shared with the run's other image sources).</summary>
    public GalleryScanResult Collect(IEnumerable<ThumbnailSource> sources, ImageStore store,
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var warnings = new List<string>();
        var summaries = new List<CacheFileSummary>();
        var byKey = new Dictionary<(string User, string Kind, ulong Id), Dictionary<string, Copy>>();
        var indexed = new Dictionary<string, HashSet<ulong>>();   // per user: ids listed in thumbcache_idx.db

        foreach (var source in sources)
        {
            ct.ThrowIfCancellationRequested();
            // Everything is read inside this account's own profile: a junction or symlink anywhere on the way (even one
            // the user made in their own AppData) could otherwise lead into another account's caches.
            using var confined = SourceFiles.Confine(ProfileOf(source.ExplorerFolder));
            List<string> files;
            try
            {
                if (Directory.Exists(source.ExplorerFolder) && !SourceFiles.IsInside(source.ExplorerFolder))
                {
                    warnings.Add($"Skipped the thumbnail folder for {source.User}: it is, or goes through, a link to another location.");
                    continue;
                }
                files = Directory.EnumerateFiles(source.ExplorerFolder, "*.db", SourceFiles.Options).ToList();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                warnings.Add($"Could not open the thumbnail folder for {source.User}: {ex.Message}");
                continue;
            }

            if (source.RestorePoint is null && ThumbcacheIndexParser.ReadIds(Path.Combine(source.ExplorerFolder, "thumbcache_idx.db")) is { } idxIds)
                indexed[source.User] = idxIds;
            var fileOwner = source.RestorePoint is { } point ? $"{source.User} (restore point {point:yyyy-MM-dd})" : source.User;

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
                    // Explorer keeps these open: SourceFiles shares read/write/delete so we never block it, and refuses
                    // links and anything whose real location is outside the profile before opening.
                    using var file = SourceFiles.OpenRead(path);
                    if (PCPorter.Core.IO.FileIdentity.LinkCount(file.SafeFileHandle) is > 1)
                        throw new UnauthorizedAccessException("it has more than one name (hard link), so it may belong to another account; it was not read.");
                    if (file.Length == 0) continue;
                    using var fs = new BufferedStream(file, 1 << 20);
                    var info = new FileInfo(path);
                    var parsed = ThumbcacheParser.Parse(fs, Path.GetFileName(path), ct);
                    warnings.AddRange(parsed.Warnings);
                    summaries.Add(new CacheFileSummary(fileOwner, Path.GetFileName(path), parsed.Version,
                        parsed.ImageEntries, parsed.EmptyEntries, parsed.Warnings.Count));

                    foreach (var e in parsed.Entries)
                    {
                        GalleryImage? image = null;
                        if (e.HasImage)
                        {
                            var bytes = ThumbcacheParser.ReadImage(fs, e);
                            image = new GalleryImage(sizeClass, e.Width, e.Height, store.Save(bytes, e.Format), e.Format, e.FoundInFreeSpace, source.RestorePoint);
                        }
                        var key = (source.User, kind, e.CacheId);
                        if (!byKey.TryGetValue(key, out var copies)) byKey[key] = copies = [];
                        var copy = new Copy(image, sizeClass, e.FoundInFreeSpace, Path.GetFileName(path), info.CreationTimeUtc, info.LastWriteTimeUtc, source.RestorePoint);
                        // One copy per size class and place (live cache, each restore point); prefer the live copy, then the one with an image.
                        var slot = source.RestorePoint is { } rp ? $"{sizeClass}@{rp.UtcTicks}" : sizeClass;
                        if (!copies.TryGetValue(slot, out var existing) || Better(copy, existing)) copies[slot] = copy;
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidDataException)
                {
                    warnings.Add($"Could not read {Path.GetFileName(path)} for {source.User}: {ex.Message}");
                }
            }
        }

        progress?.Report("Looking up original file paths");
        ct.ThrowIfCancellationRequested();
        var paths = resolver.Resolve(byKey.Keys.Where(k => k.Kind == "thumbnail").Select(k => k.Id).ToHashSet(), ct);

        progress?.Report("Checking which originals still exist");
        var items = new List<GalleryItem>(byKey.Count);
        foreach (var ((user, kind, id), all) in byKey)
        {
            ct.ThrowIfCancellationRequested();
            // The live cache defines the item; restore-point copies add pictures and date evidence.
            var live = all.Values.Where(c => c.RestorePoint is null).ToList();
            var restorePoints = all.Values.Where(c => c.RestorePoint is not null).Select(c => c.RestorePoint!.Value).Distinct().Order().ToList();
            var primary = live.Count > 0 ? live : all.Values.ToList();
            var images = all.Values.Where(c => c.Image is not null).Select(c => c.Image!)
                .OrderBy(i => i.RestorePoint is not null).ThenByDescending(i => (long)i.Width * i.Height)
                .DistinctBy(i => i.File).ToList();
            var original = kind == "thumbnail" ? paths.GetValueOrDefault(id) : null;
            var status = _locator.Locate(original);
            var dates = DatesFor(original, status, primary);
            bool freeSpace = primary.All(c => c.FreeSpace);
            var notes = new List<string>();
            if (images.Count == 0) notes.Add("Windows showed this item but kept no picture of it.");
            if (live.Count == 0)
                notes.Add($"Found only in a restore point from {restorePoints[0]:yyyy-MM-dd}: the live cache no longer has it.");
            else if (kind == "thumbnail" && indexed.TryGetValue(user, out var idx) && !idx.Contains(id))
                notes.Add("Not listed in the cache's own index: an older entry Windows no longer points to.");
            string? note = notes.Count == 0 ? null : string.Join(" ", notes);
            items.Add(new GalleryItem(
                Id: $"{kind[0]}-{user}-{id:x16}", Kind: kind,
                Source: kind == "icon" ? "File Explorer icons" : "File Explorer thumbnails",
                Evidence: EvidenceLevel.Displayed, User: user, CacheId: $"{id:x16}", OriginalPath: original, Url: null,
                Status: kind == "icon" ? OriginalStatus.Unknown : status, FoundInFreeSpace: freeSpace,
                Best: images.FirstOrDefault(), Images: images, Dates: dates, Note: note,
                RestorePoints: restorePoints.Count == 0 ? null : restorePoints, OnlyInRestorePoints: live.Count == 0));
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

    const string ExplorerSuffix = @"\AppData\Local\Microsoft\Windows\Explorer";

    /// <summary>
    /// The account's profile folder that holds this Explorer folder (string-based, so device paths into restore points
    /// work), or the Explorer folder itself when it is not in the usual place.
    /// </summary>
    public static string ProfileOf(string explorerFolder)
    {
        var folder = explorerFolder.TrimEnd('\\', '/').Replace('/', '\\');
        return folder.EndsWith(ExplorerSuffix, StringComparison.OrdinalIgnoreCase) && folder.Length > ExplorerSuffix.Length
            ? folder[..^ExplorerSuffix.Length]
            : folder;
    }

    /// <summary>
    /// Thumbnail folders to read on this running PC. By default only the person running PCPorter;
    /// <paramref name="allUsers"/> adds every other profile (needs admin, and their consent).
    /// </summary>
    public static IReadOnlyList<ThumbnailSource> LiveSources(bool allUsers = false, string? usersRoot = null, string? currentProfile = null) =>
        FindLiveSources(allUsers, usersRoot, currentProfile).Sources;

    /// <summary>The thumbnail folders found, and one plain-words line for each account that was skipped and why.</summary>
    public sealed record LiveSourceSearch(IReadOnlyList<ThumbnailSource> Sources, IReadOnlyList<string> Skipped);

    /// <summary>Folders in C:\Users that are not accounts (templates and shared folders): never reported as skipped.</summary>
    static readonly HashSet<string> NotAccounts = new(StringComparer.OrdinalIgnoreCase) { "Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount" };

    public static LiveSourceSearch FindLiveSources(bool allUsers = false, string? usersRoot = null, string? currentProfile = null)
    {
        currentProfile ??= Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var list = new List<ThumbnailSource>();
        var skipped = new List<string>();
        IEnumerable<string> profiles = [currentProfile];
        if (allUsers)
        {
            var root = usersRoot ?? Path.GetDirectoryName(currentProfile)!;
            try { profiles = Directory.EnumerateDirectories(root, "*", new EnumerationOptions { AttributesToSkip = 0 }).ToList(); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                skipped.Add($"Could not list the user accounts ({ex.Message}); only {Path.GetFileName(currentProfile)} was read.");
            }
        }
        foreach (var profile in profiles)
        {
            var user = Path.GetFileName(profile);
            if (allUsers && NotAccounts.Contains(user)) continue;
            if (PCPorter.Core.IO.FileIdentity.Entry(profile) is { IsLink: true })
            {
                skipped.Add($"Skipped the account folder {user}: it is a link to another location.");
                continue;
            }
            var folder = Path.Combine(profile, "AppData", "Local", "Microsoft", "Windows", "Explorer");
            try
            {
                if (Directory.Exists(folder)) { list.Add(new ThumbnailSource(user, folder)); continue; }
                _ = Directory.EnumerateFileSystemEntries(profile).Any();   // tells "no access" apart from "not there"
                skipped.Add($"Skipped {user}: it has no File Explorer cache folder (the account may never have signed in on this PC).");
            }
            catch (UnauthorizedAccessException)
            {
                skipped.Add($"Skipped {user}: access to the account folder was denied (run PCPorter as administrator to include it).");
            }
            catch (IOException ex)
            {
                skipped.Add($"Skipped {user}: the account folder could not be read ({ex.Message}).");
            }
        }
        return new LiveSourceSearch(list, skipped);
    }
}
