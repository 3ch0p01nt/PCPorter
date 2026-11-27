using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.BrowserCache;

/// <summary>
/// Images in the Chromium disk cache of Edge, Chrome and new Teams (WebView2).
/// Reads the blockfile format (index + data_N + f_XXXXXX) and the simple format (&lt;hash&gt;_0 files). Read-only.
/// </summary>
public sealed partial class ChromiumCacheSource : IImageEvidenceSource
{
    public string Name => "Chromium browser cache (Edge, Chrome, Teams)";

    public IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        foreach (var (folder, label, browser) in FindCacheFolders(context))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var e in CollectFromCacheFolder(folder, label, browser, context, cancellationToken))
                yield return e;
        }
    }

    /// <summary>Cache folders under one user profile: (cache folder, source label, browser name).</summary>
    public static IReadOnlyList<(string Folder, string Label, string Browser)> FindCacheFolders(ImageSourceContext context)
    {
        var result = new List<(string, string, string)>();
        string local = Path.Combine(context.ProfileFolder, "AppData", "Local");
        AddBrowser(result, Path.Combine(local, "Microsoft", "Edge", "User Data"), "Edge", context);
        AddBrowser(result, Path.Combine(local, "Google", "Chrome", "User Data"), "Chrome", context);
        string teams = Path.Combine(local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams", "EBWebView", "WV2Profile_tfw");
        if (CacheFolderIn(teams) is { } t) result.Add((t, "Teams cache", "Teams"));
        return result;
    }

    private static void AddBrowser(List<(string, string, string)> result, string userData, string browser, ImageSourceContext context)
    {
        try
        {
            if (!Directory.Exists(userData)) return;
            foreach (var profile in Directory.EnumerateDirectories(userData).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                string name = Path.GetFileName(profile);
                if (!name.Equals("Default", StringComparison.OrdinalIgnoreCase) && !ProfileName().IsMatch(name)) continue;
                if (CacheFolderIn(profile) is { } cache) result.Add((cache, $"{browser} cache ({name})", browser));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            context.Warnings.Add($"{browser} cache: could not list profiles ({ex.GetType().Name}).");
        }
    }

    private static string? CacheFolderIn(string profile)
    {
        foreach (var candidate in new[] { Path.Combine(profile, "Cache", "Cache_Data"), Path.Combine(profile, "Cache") })
        {
            try
            {
                if (!Directory.Exists(candidate)) continue;
                if (File.Exists(Path.Combine(candidate, "index"))) return candidate;
                if (Directory.EnumerateFiles(candidate, "*_0").Any(f => SimpleFileName().IsMatch(Path.GetFileName(f)))) return candidate;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    [GeneratedRegex(@"^Profile \d+$", RegexOptions.IgnoreCase)]
    private static partial Regex ProfileName();

    [GeneratedRegex(@"^[0-9a-f]{16}_0$", RegexOptions.IgnoreCase)]
    private static partial Regex SimpleFileName();

    /// <summary>Reads one cache folder (blockfile or simple format). Never throws for bad data; problems go to context.Warnings.</summary>
    public static IEnumerable<ImageEvidence> CollectFromCacheFolder(
        string cacheFolder, string sourceLabel, string browser, ImageSourceContext context, CancellationToken cancellationToken = default)
    {
        bool blockfile;
        try { blockfile = File.Exists(Path.Combine(cacheFolder, "index")); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { blockfile = false; }

        var source = blockfile
            ? ReadBlockfile(cacheFolder, sourceLabel, browser, context, cancellationToken)
            : ReadSimple(cacheFolder, sourceLabel, browser, context, cancellationToken);
        foreach (var e in source) yield return e;
    }

    private static string TimeMeaning(string browser) => $"first and last loaded from {browser} cache";

    // ---------------------------------------------------------------- blockfile

    private const uint IndexMagic = 0xC103CAC3;
    private const int IndexHeaderSize = 368;
    private const int BlockHeaderSize = 8192;
    private const int MaxChain = 10_000;

    private static IEnumerable<ImageEvidence> ReadBlockfile(
        string folder, string label, string browser, ImageSourceContext context, CancellationToken ct)
    {
        uint[]? table = ReadIndexTable(folder, label, context);
        if (table is null) yield break;

        using var store = new BlockStore(folder);
        var visited = new HashSet<uint>();
        int failed = 0;
        foreach (uint bucket in table)
        {
            uint addr = bucket;
            int chain = 0;
            while (addr != 0 && chain++ < MaxChain && visited.Add(addr))
            {
                ct.ThrowIfCancellationRequested();
                var (evidence, next, ok) = ReadEntry(store, addr, label, browser, context.User);
                if (!ok) failed++;
                if (evidence is not null) yield return evidence;
                addr = next;
            }
        }
        if (failed > 0) context.Warnings.Add($"{label}: {failed} cache entries could not be read (damaged or in use).");
        if (store.MissingFiles > 0) context.Warnings.Add($"{label}: {store.MissingFiles} cache data files were missing or unreadable.");
    }

    private static uint[]? ReadIndexTable(string folder, string label, ImageSourceContext context)
    {
        try
        {
            using var h = CacheBody.OpenShared(Path.Combine(folder, "index"));
            long length = RandomAccess.GetLength(h);
            if (length < IndexHeaderSize || length > 64L * 1024 * 1024)
            {
                context.Warnings.Add($"{label}: cache index has an unexpected size; skipped.");
                return null;
            }
            var bytes = CacheBody.ReadAt(h, 0, (int)length);
            if (bytes.Length < IndexHeaderSize || BinaryPrimitives.ReadUInt32LittleEndian(bytes) != IndexMagic)
            {
                context.Warnings.Add($"{label}: cache index is not a Chromium blockfile index; skipped.");
                return null;
            }
            int tableLen = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(28));
            if (tableLen <= 0) tableLen = 0x10000;
            int available = (bytes.Length - IndexHeaderSize) / 4;
            if (tableLen > available)
            {
                context.Warnings.Add($"{label}: cache index is truncated; reading what is there.");
                tableLen = available;
            }
            var table = new uint[tableLen];
            for (int i = 0; i < tableLen; i++)
                table[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(IndexHeaderSize + i * 4));
            return table;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            context.Warnings.Add($"{label}: could not read cache index ({ex.GetType().Name}).");
            return null;
        }
    }

    /// <summary>Returns (evidence or null, next entry in the hash chain, whether the entry was readable).</summary>
    private static (ImageEvidence? Evidence, uint Next, bool Ok) ReadEntry(
        BlockStore store, uint addr, string label, string browser, string user)
    {
        try
        {
            if (CacheAddr.FileType(addr) != 2) return (null, 0, false); // entries live in 256-byte block files
            var entry = store.Read(addr, int.MaxValue);
            if (entry is null || entry.Length < 96) return (null, 0, false);
            var s = entry.AsSpan();
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(s[4..]);
            uint rankings = BinaryPrimitives.ReadUInt32LittleEndian(s[8..]);
            int state = BinaryPrimitives.ReadInt32LittleEndian(s[20..]);
            long created = BinaryPrimitives.ReadInt64LittleEndian(s[24..]);
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(s[32..]);
            uint longKey = BinaryPrimitives.ReadUInt32LittleEndian(s[36..]);
            int size0 = BinaryPrimitives.ReadInt32LittleEndian(s[40..]);
            int size1 = BinaryPrimitives.ReadInt32LittleEndian(s[44..]);
            uint addr0 = BinaryPrimitives.ReadUInt32LittleEndian(s[56..]);
            uint addr1 = BinaryPrimitives.ReadUInt32LittleEndian(s[60..]);
            if (!CacheAddr.IsInitialized(next)) next = 0;
            if (state == 2) return (null, next, true); // doomed

            if (keyLen <= 0 || keyLen > 1024 * 1024) return (null, next, false);
            byte[]? keyBytes = longKey != 0
                ? store.Read(longKey, keyLen)
                : entry[96..Math.Min(entry.Length, 96 + keyLen)];
            if (keyBytes is null || keyBytes.Length == 0) return (null, next, false);
            string key = Encoding.UTF8.GetString(keyBytes).TrimEnd('\0');

            if (size1 <= 0 || size1 > CacheBody.MaxBodyBytes || addr1 == 0) return (null, next, true);

            var head = CacheBody.HttpHead.Empty;
            if (addr0 != 0 && size0 > 0 && size0 <= 1024 * 1024 && store.Read(addr0, size0) is { } info)
                head = ParsePickledHead(info);

            var image = CacheBody.TryGetImage(head, size1,
                n => store.Read(addr1, Math.Min(n, size1)),
                () => store.Read(addr1, size1) is { } b && b.Length == size1 ? b : null);
            if (image is null) return (null, next, true);

            DateTimeOffset? lastUsed = null;
            if (rankings != 0 && store.Read(rankings, 36) is { Length: >= 8 } node)
                lastUsed = CacheBody.FromWindowsMicroseconds(BinaryPrimitives.ReadInt64LittleEndian(node));

            var evidence = new ImageEvidence(
                Source: label,
                Evidence: EvidenceLevel.LoadedByWebPage,
                User: user,
                OriginalPath: null,
                Url: CacheBody.ExtractUrl(key),
                FirstSeenUtc: CacheBody.FromWindowsMicroseconds(created),
                LastSeenUtc: lastUsed,
                TimeMeaning: TimeMeaning(browser),
                ImageBytes: image.Value.Bytes,
                ContentType: image.Value.ContentType,
                Note: NoteFor(head));
            return (evidence, next, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            return (null, 0, false);
        }
    }

    private static string? NoteFor(CacheBody.HttpHead head)
    {
        var parts = new List<string>();
        if (head.Status is { } st) parts.Add($"HTTP {st}");
        if (!string.IsNullOrWhiteSpace(head.Date)) parts.Add($"server date {head.Date}");
        return parts.Count == 0 ? null : string.Join("; ", parts);
    }

    /// <summary>
    /// Stream 0 is a pickled HttpResponseInfo; the raw headers inside are NUL-separated lines starting with "HTTP/"
    /// and ending with an empty line. Scanning for the status line is robust across pickle versions.
    /// </summary>
    internal static CacheBody.HttpHead ParsePickledHead(byte[] info)
    {
        int start = info.AsSpan().IndexOf("HTTP/"u8);
        if (start < 0) return CacheBody.HttpHead.Empty;
        int end = info.AsSpan(start).IndexOf("\0\0"u8);
        int stop = end < 0 ? info.Length : start + end;
        string text = Encoding.Latin1.GetString(info, start, stop - start);
        return CacheBody.ParseHead(text.Split('\0'));
    }

    private static class CacheAddr
    {
        public static bool IsInitialized(uint a) => (a & 0x80000000) != 0;
        public static int FileType(uint a) => (int)((a >> 28) & 7);
        public static int BlockSize(int type) => type switch { 1 => 36, 2 => 256, 3 => 1024, 4 => 4096, _ => 0 };
    }

    /// <summary>Lazily opened data_N and f_XXXXXX files, all shared read-only.</summary>
    private sealed class BlockStore(string folder) : IDisposable
    {
        private readonly Dictionary<int, SafeFileHandle?> _blockFiles = [];
        public int MissingFiles { get; private set; }

        /// <summary>Reads up to maxLength bytes stored at a cache address; null if the address or file is bad.</summary>
        public byte[]? Read(uint addr, int maxLength)
        {
            if (!CacheAddr.IsInitialized(addr) || maxLength <= 0) return null;
            int type = CacheAddr.FileType(addr);
            if (type == 0)
            {
                string path = Path.Combine(folder, $"f_{addr & 0x0FFFFFFF:x6}");
                try
                {
                    using var h = CacheBody.OpenShared(path);
                    return CacheBody.ReadAt(h, 0, maxLength);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    MissingFiles++;
                    return null;
                }
            }
            int blockSize = CacheAddr.BlockSize(type);
            if (blockSize == 0) return null;
            int numBlocks = (int)((addr >> 24) & 3) + 1;
            int fileNo = (int)((addr >> 16) & 0xFF);
            int start = (int)(addr & 0xFFFF);
            var handle = BlockFile(fileNo);
            if (handle is null) return null;
            long offset = BlockHeaderSize + (long)start * blockSize;
            int length = Math.Min(maxLength, numBlocks * blockSize);
            var bytes = CacheBody.ReadAt(handle, offset, length);
            return bytes.Length == 0 ? null : bytes;
        }

        private SafeFileHandle? BlockFile(int n)
        {
            if (_blockFiles.TryGetValue(n, out var h)) return h;
            try { h = CacheBody.OpenShared(Path.Combine(folder, $"data_{n}")); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { h = null; MissingFiles++; }
            _blockFiles[n] = h;
            return h;
        }

        public void Dispose()
        {
            foreach (var h in _blockFiles.Values) h?.Dispose();
            _blockFiles.Clear();
        }
    }

    // ---------------------------------------------------------------- simple cache

    private const ulong SimpleInitialMagic = 0xfcfb6d1ba7725c30;
    private const ulong SimpleFinalMagic = 0xf4fa6f45970d41d8;
    private const int SimpleHeaderSize = 24;
    private const int SimpleEofSize = 24;
    private const int SimpleFlagHasKeySha256 = 2;

    private static IEnumerable<ImageEvidence> ReadSimple(
        string folder, string label, string browser, ImageSourceContext context, CancellationToken ct)
    {
        List<string> files;
        try
        {
            files = Directory.EnumerateFiles(folder, "*_0").Where(f => SimpleFileName().IsMatch(Path.GetFileName(f))).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            context.Warnings.Add($"{label}: could not list cache files ({ex.GetType().Name}).");
            yield break;
        }

        int failed = 0;
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var (evidence, ok) = ReadSimpleEntry(file, label, browser, context.User);
            if (!ok) failed++;
            if (evidence is not null) yield return evidence;
        }
        if (failed > 0) context.Warnings.Add($"{label}: {failed} cache files could not be read (damaged or in use).");
    }

    private static (ImageEvidence? Evidence, bool Ok) ReadSimpleEntry(string path, string label, string browser, string user)
    {
        try
        {
            using var h = CacheBody.OpenShared(path);
            long length = RandomAccess.GetLength(h);
            if (length < SimpleHeaderSize + SimpleEofSize * 2) return (null, false);
            if (length > CacheBody.MaxBodyBytes + 4L * 1024 * 1024) return (null, true); // too big to be an image we keep

            var header = CacheBody.ReadAt(h, 0, SimpleHeaderSize);
            if (header.Length < SimpleHeaderSize || BinaryPrimitives.ReadUInt64LittleEndian(header) != SimpleInitialMagic) return (null, false);
            uint keyLen = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
            if (keyLen == 0 || keyLen > length - SimpleHeaderSize - SimpleEofSize * 2) return (null, false);
            var keyBytes = CacheBody.ReadAt(h, SimpleHeaderSize, (int)keyLen);
            if (keyBytes.Length != keyLen) return (null, false);
            string key = Encoding.UTF8.GetString(keyBytes).TrimEnd('\0');

            // Layout: header, key, stream 1, EOF(1), stream 0, [key SHA-256], EOF(0).
            var eof0 = CacheBody.ReadAt(h, length - SimpleEofSize, SimpleEofSize);
            if (eof0.Length < 20 || BinaryPrimitives.ReadUInt64LittleEndian(eof0) != SimpleFinalMagic) return (null, false);
            uint flags0 = BinaryPrimitives.ReadUInt32LittleEndian(eof0.AsSpan(8));
            int size0 = BinaryPrimitives.ReadInt32LittleEndian(eof0.AsSpan(16));
            long stream0Start = length - SimpleEofSize - ((flags0 & SimpleFlagHasKeySha256) != 0 ? 32 : 0) - size0;
            long eof1Pos = stream0Start - SimpleEofSize;
            long stream1Start = SimpleHeaderSize + keyLen;
            if (size0 < 0 || eof1Pos < stream1Start) return (null, false);

            var eof1 = CacheBody.ReadAt(h, eof1Pos, SimpleEofSize);
            if (eof1.Length < 20 || BinaryPrimitives.ReadUInt64LittleEndian(eof1) != SimpleFinalMagic) return (null, false);
            int size1 = BinaryPrimitives.ReadInt32LittleEndian(eof1.AsSpan(16));
            if (size1 < 0 || stream1Start + size1 != eof1Pos) return (null, false);

            var head = size0 is > 0 and <= 1024 * 1024
                ? ParsePickledHead(CacheBody.ReadAt(h, stream0Start, size0))
                : CacheBody.HttpHead.Empty;

            var image = CacheBody.TryGetImage(head, size1,
                n => CacheBody.ReadAt(h, stream1Start, Math.Min(n, size1)),
                () => CacheBody.ReadAt(h, stream1Start, size1) is { } b && b.Length == size1 ? b : null);
            if (image is null) return (null, true);

            var evidence = new ImageEvidence(
                Source: label,
                Evidence: EvidenceLevel.LoadedByWebPage,
                User: user,
                OriginalPath: null,
                Url: CacheBody.ExtractUrl(key),
                FirstSeenUtc: CacheBody.SafeFileTime(() => File.GetCreationTimeUtc(path)),
                LastSeenUtc: CacheBody.SafeFileTime(() => File.GetLastWriteTimeUtc(path)),
                TimeMeaning: TimeMeaning(browser),
                ImageBytes: image.Value.Bytes,
                ContentType: image.Value.ContentType,
                Note: string.Join("; ", new[] { NoteFor(head), "times are cache file times" }.Where(x => x is not null)));
            return (evidence, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            return (null, false);
        }
    }
}
