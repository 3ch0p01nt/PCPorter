using System.Buffers.Binary;
using System.Text;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.BrowserCache;

/// <summary>
/// Images in the Firefox disk cache (cache2\entries). Each entry file is: body, chunk hashes, metadata,
/// and a final big-endian uint32 holding the metadata offset. Read-only.
/// </summary>
public sealed class FirefoxCacheSource : IImageEvidenceSource
{
    private const int ChunkSize = 256 * 1024;
    private const int MaxMetadataBytes = 4 * 1024 * 1024;
    private const string Meaning = "first and last loaded from Firefox cache";

    public string Name => "Firefox browser cache";

    public IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        foreach (var (folder, label) in FindCacheFolders(context))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var e in CollectFromEntriesFolder(folder, label, context, cancellationToken))
                yield return e;
        }
    }

    /// <summary>cache2\entries folders under one user profile: (folder, source label).</summary>
    public static IReadOnlyList<(string Folder, string Label)> FindCacheFolders(ImageSourceContext context)
    {
        var result = new List<(string, string)>();
        string profiles = Path.Combine(context.ProfileFolder, "AppData", "Local", "Mozilla", "Firefox", "Profiles");
        try
        {
            if (!Directory.Exists(profiles)) return result;
            foreach (var profile in Directory.EnumerateDirectories(profiles).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                string entries = Path.Combine(profile, "cache2", "entries");
                if (Directory.Exists(entries)) result.Add((entries, $"Firefox cache ({Path.GetFileName(profile)})"));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            context.Warnings.Add($"Firefox cache: could not list profiles ({ex.GetType().Name}).");
        }
        return result;
    }

    /// <summary>Reads one cache2\entries folder. Never throws for bad data; problems go to context.Warnings.</summary>
    public static IEnumerable<ImageEvidence> CollectFromEntriesFolder(
        string folder, string label, ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        List<string> files;
        try { files = Directory.EnumerateFiles(folder).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            context.Warnings.Add($"{label}: could not list cache files ({ex.GetType().Name}).");
            yield break;
        }

        int failed = 0;
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (evidence, ok) = ReadEntry(file, label, context.User);
            if (!ok) failed++;
            if (evidence is not null) yield return evidence;
        }
        if (failed > 0) context.Warnings.Add($"{label}: {failed} cache files could not be read (damaged or in use).");
    }

    private static (ImageEvidence? Evidence, bool Ok) ReadEntry(string path, string label, string user)
    {
        try
        {
            using var h = CacheBody.OpenShared(path);
            long length = RandomAccess.GetLength(h);
            if (length < 4) return (null, length == 0); // empty files are placeholders, not damage
            var tail = CacheBody.ReadAt(h, length - 4, 4);
            if (tail.Length != 4) return (null, false);
            long metaOffset = BinaryPrimitives.ReadUInt32BigEndian(tail);
            if (metaOffset > length - 4) return (null, false);
            long metaLength = length - 4 - metaOffset;
            if (metaLength < 4 + 28 || metaLength > MaxMetadataBytes) return (null, false);

            var meta = CacheBody.ReadAt(h, metaOffset, (int)metaLength);
            if (meta.Length != metaLength) return (null, false);
            var parsed = ParseMetadata(meta, metaOffset);
            if (parsed is null) return (null, false);
            var m = parsed.Value;

            var head = m.ResponseHead is null
                ? CacheBody.HttpHead.Empty
                : CacheBody.ParseHead(m.ResponseHead.Split('\n'));
            int bodySize = (int)Math.Min(metaOffset, int.MaxValue);
            var image = CacheBody.TryGetImage(head, metaOffset,
                n => CacheBody.ReadAt(h, 0, Math.Min(n, bodySize)),
                () => CacheBody.ReadAt(h, 0, bodySize) is { } b && b.Length == bodySize ? b : null);
            if (image is null) return (null, true);

            var notes = new List<string>();
            if (head.Status is { } st) notes.Add($"HTTP {st}");
            notes.Add($"fetched {m.FetchCount} time{(m.FetchCount == 1 ? "" : "s")}");
            if (!string.IsNullOrWhiteSpace(head.Date)) notes.Add($"server date {head.Date}");
            notes.Add("first time is the cache file's creation time");

            var evidence = new ImageEvidence(
                Source: label,
                Evidence: EvidenceLevel.LoadedByWebPage,
                User: user,
                OriginalPath: null,
                Url: ExtractUrl(m.Key),
                FirstSeenUtc: Earliest(CacheBody.SafeFileTime(() => File.GetCreationTimeUtc(path)), CacheBody.FromUnixSeconds(m.LastModified)),
                LastSeenUtc: CacheBody.FromUnixSeconds(m.LastFetched),
                TimeMeaning: Meaning,
                ImageBytes: image.Value.Bytes,
                ContentType: image.Value.ContentType,
                Note: string.Join("; ", notes));
            return (evidence, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            return (null, false);
        }
    }

    private static DateTimeOffset? Earliest(DateTimeOffset? a, DateTimeOffset? b) =>
        a is null ? b : b is null ? a : (a < b ? a : b);

    internal readonly record struct Metadata(uint Version, uint FetchCount, uint LastFetched, uint LastModified, string Key, string? ResponseHead);

    /// <summary>Parses the metadata block (hash, chunk hashes, header, key, elements). Null if it does not look valid.</summary>
    internal static Metadata? ParseMetadata(byte[] meta, long bodySize)
    {
        long chunks = (bodySize + ChunkSize - 1) / ChunkSize;
        long pos = 4 + chunks * 2; // metadata hash + one uint16 hash per chunk
        if (pos + 28 > meta.Length) return null;
        uint U32(long at) => BinaryPrimitives.ReadUInt32BigEndian(meta.AsSpan((int)at));

        uint version = U32(pos);
        if (version is 0 or > 100) return null;
        uint fetchCount = U32(pos + 4);
        uint lastFetched = U32(pos + 8);
        uint lastModified = U32(pos + 12);
        uint keySize = U32(pos + 24);
        pos += 28;
        if (version >= 2) pos += 4; // flags
        if (keySize == 0 || pos + keySize > meta.Length) return null;
        string key = Encoding.UTF8.GetString(meta, (int)pos, (int)keySize);
        pos += keySize + 1; // key is NUL-terminated

        string? responseHead = null;
        if (pos < meta.Length)
        {
            var parts = Encoding.Latin1.GetString(meta, (int)pos, meta.Length - (int)pos).Split('\0');
            for (int i = 0; i + 1 < parts.Length; i += 2)
            {
                if (parts[i] == "response-head") { responseHead = parts[i + 1]; break; }
            }
        }
        return new Metadata(version, fetchCount, lastFetched, lastModified, key, responseHead);
    }

    /// <summary>Firefox keys look like "a,:https://..." or "O^partitionKey=...,a,:https://..."; the URL follows the last ":http".</summary>
    internal static string ExtractUrl(string key)
    {
        int i = key.LastIndexOf(":http", StringComparison.OrdinalIgnoreCase);
        if (i >= 0) return key[(i + 1)..];
        int j = key.LastIndexOf(",:", StringComparison.Ordinal);
        return j >= 0 ? key[(j + 2)..] : key;
    }
}
