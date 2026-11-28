using System.Reflection;
using System.Text.Json;
using PCPorter.Core.Case;
using PCPorter.Core.Security;
using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Reports;

public sealed record ThumbnailJobOptions(
    bool AllUsers = false,
    IReadOnlyList<IImageEvidenceSource>? ExtraSources = null,
    Func<IReadOnlyList<GalleryItem>, string, CancellationToken, IReadOnlyDictionary<string, int>>? DuplicateGrouper = null,
    IReadOnlyList<string>? ExtraNotes = null,
    /// <summary>Builds the path resolver given a private work folder inside the case (for index copies).</summary>
    Func<string, IThumbnailPathResolver>? ResolverFactory = null,
    /// <summary>More thumbnail folders derived from the live ones (e.g. inside restore points).</summary>
    Func<IReadOnlyList<ThumbnailSource>, IReadOnlyList<ThumbnailSource>>? AdditionalSources = null);

public sealed record ThumbnailJobResult(string ReportPath, string CaseFolder, GalleryScanResult Scan, IReadOnlyList<string> FolderWarnings);

/// <summary>
/// End-to-end: create a private case folder, collect thumbnails (and any extra image sources), group near-duplicates,
/// write case.db rows and Thumbnails.html. Read-only on the scanned PC.
/// </summary>
public static class ThumbnailJob
{
    public static ThumbnailJobResult Run(
        string outRoot, IThumbnailPathResolver? resolver = null, IReadOnlyList<ThumbnailSource>? sources = null,
        IProgress<string>? progress = null, DateTimeOffset? now = null, ThumbnailJobOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ThumbnailJobOptions();
        var when = now ?? DateTimeOffset.UtcNow;
        var folder = CaseFolder.Create(outRoot, when);
        var reportFolder = Path.Combine(folder.Path, "Thumbnails");
        CaseFolder.CreatePrivate(reportFolder);
        var imagesFolder = Path.Combine(reportFolder, "thumbs");
        var work = Path.Combine(folder.Path, "work");
        CaseFolder.CreatePrivate(work);
        bool reportWritten = false;
        try
        {
            var result = Collect();
            reportWritten = true;
            return result;
        }
        finally
        {
            // Also on Cancel or a failure: the work folder can hold a copy of the search index.
            TryDelete(work);
            // Without a report nobody would know the extracted private pictures are there: remove the whole case.
            if (!reportWritten) TryDelete(folder.Path);
        }

        ThumbnailJobResult Collect()
        {
        resolver ??= options.ResolverFactory?.Invoke(work) ?? new NoPathResolver();
        IReadOnlyList<string> skippedAccounts = [];
        if (sources is null)
        {
            var found = ThumbnailCollector.FindLiveSources(options.AllUsers);
            (sources, skippedAccounts) = (found.Sources, found.Skipped);
        }
        var allSources = options.AdditionalSources is null ? sources : sources.Concat(options.AdditionalSources(sources)).ToList();
        var store = new ImageStore(imagesFolder);   // one store for every source: the same picture is saved once
        var scan = new ThumbnailCollector(resolver).Collect(allSources, store, progress, ct);

        // Other image sources (browser caches, screenshots, recently opened files) go into the same gallery.
        var items = scan.Items.ToList();
        var warnings = skippedAccounts.Concat(scan.Warnings).ToList();
        var notes = scan.Notes.Concat(options.ExtraNotes ?? []).ToList();
        if (options.ExtraSources is { Count: > 0 })
        {
            var locator = new OriginalLocator();
            foreach (var src in sources)
            {
                var profile = ThumbnailCollector.ProfileOf(src.ExplorerFolder);
                var ctx = new ImageSourceContext(src.User, profile, warnings, notes);
                foreach (var source in options.ExtraSources)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report($"{src.User}: {source.Name}");
                    try
                    {
                        foreach (var ev in source.Collect(ctx, ct))
                            items.Add(EvidenceMapper.ToItem(ev, store, locator));
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        warnings.Add($"{source.Name} for {src.User} stopped early: {ex.Message}");
                    }
                }
            }
        }

        ct.ThrowIfCancellationRequested();
        items = DateCorroborator.Apply(items);

        if (options.DuplicateGrouper is not null)
        {
            progress?.Report("Finding similar pictures");
            var groups = options.DuplicateGrouper(items, imagesFolder, ct);
            items = items.Select(i => groups.TryGetValue(i.Id, out var g) ? i with { DupGroup = g } : i).ToList();
        }
        ct.ThrowIfCancellationRequested();

        // Warnings and notes quote paths, addresses and error messages: masked once here for the report, the app and logs.
        scan = new GalleryScanResult(items, scan.CacheFiles, warnings.Select(Redactor.Redact).ToList(), notes.Select(Redactor.Redact).ToList());

        using (var db = CaseDb.Open(Path.Combine(folder.Path, "case.db")))
            db.Insert(items.Select(i => new Artifact(
                TsUtc: i.Dates?.Before, Category: "Image." + i.Kind, Source: i.Source, ArtifactName: i.Kind,
                User: i.User, Action: i.Evidence.ToString(), Subject: i.OriginalPath ?? i.Url ?? i.CacheId ?? i.Id,
                Detail: JsonSerializer.Serialize(new { i.CacheId, Status = i.Status.ToString(), i.FoundInFreeSpace, HasPicture = i.HasImage, i.Dates?.Confidence }),
                Confidence: i.Evidence == EvidenceLevel.Opened ? Confidence.Ran : Confidence.Existed)));

        var version = typeof(ThumbnailJob).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "dev";
        var meta = new ReportMeta(Environment.MachineName, when, version, sources.Select(s => s.User).ToList(), options.AllUsers);
        var report = GalleryReport.WriteFile(scan, meta, reportFolder);
        return new ThumbnailJobResult(report, folder.Path, scan, folder.Warnings);
        }
    }

    static void TryDelete(string path)
    {
        // A file can be briefly held (antivirus, the search indexer): retry a few times.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, true); return; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Thread.Sleep(100 * (attempt + 1)); }
        }
    }
}

/// <summary>Turns evidence from any image source into a gallery item.</summary>
public static class EvidenceMapper
{
    public static GalleryItem ToItem(ImageEvidence ev, ImageStore store, OriginalLocator locator)
    {
        GalleryImage? image = null;
        if (ev.ImageBytes is { Length: > 0 } bytes)
            image = new GalleryImage("original", 0, 0, store.Save(bytes, ImageStore.ExtensionFor(bytes)), ImageFormat.Unknown, false);
        string kind = ev.Evidence switch
        {
            EvidenceLevel.LoadedByWebPage => "web",
            EvidenceLevel.OnScreen => "screenshot",
            EvidenceLevel.Opened => "opened",
            _ => "other",
        };
        var sources = new List<string>();
        if (ev.FirstSeenUtc is { } f) sources.Add($"{f:u}: {ev.TimeMeaning ?? "first seen"} (earliest)");
        if (ev.LastSeenUtc is { } l) sources.Add($"{l:u}: {ev.TimeMeaning ?? "last seen"} (latest)");
        var status = ev.OriginalPath is null ? OriginalStatus.Unknown : locator.Locate(ev.OriginalPath, ev.VolumeSerial);
        var id = $"{kind[0]}-{ev.User}-{System.IO.Hashing.XxHash64.HashToUInt64(System.Text.Encoding.UTF8.GetBytes($"{ev.Source}|{ev.OriginalPath}|{ev.Url}|{ev.FirstSeenUtc}|{ev.LastSeenUtc}")):x16}";
        // Cached addresses can carry sign-in tokens and signatures (?sig=, access_token=, user:password@): masked here,
        // so neither case.db nor the report ever holds them.
        var url = ev.Url is null ? null : Redactor.Redact(ev.Url);
        return new GalleryItem(id, kind, ev.Source, ev.Evidence, ev.User, CacheId: null, ev.OriginalPath, url, status,
            FoundInFreeSpace: false, Best: image, Images: image is null ? [] : [image],
            Dates: sources.Count == 0 ? null : new DateWindow(ev.FirstSeenUtc, ev.LastSeenUtc ?? ev.FirstSeenUtc, "Medium", sources),
            Note: ev.Note);
    }
}
