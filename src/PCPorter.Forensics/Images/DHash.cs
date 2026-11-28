using System.Numerics;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace PCPorter.Forensics.Images;

/// <summary>
/// 64-bit difference hash ("dHash") for spotting near-duplicate pictures: the image is shrunk to 9x8
/// grey pixels and each bit says whether a pixel is brighter than its right-hand neighbour.
/// <para>
/// The bytes come from an old PC that may be infected and are decoded inside an elevated process, so only JPEG, PNG,
/// BMP and GIF are hashed, picked by their first bytes and decoded with Windows' own built-in codec for that format.
/// Letting Windows choose would hand the bytes to any codec installed on this PC (HEIF, AVIF, WebP, raw camera
/// codecs from other vendors); other formats get no hash and so no similar-pictures group.
/// </para>
/// </summary>
public static class DHash
{
    private const int Width = 9, Height = 8;
    private const int BruteForceLimit = 20_000;

    /// <summary>The hash, or null when the bytes are not a JPEG, PNG, BMP or GIF that decodes.</summary>
    public static ulong? Compute(byte[]? imageBytes) => Compute(imageBytes, Decode);

    /// <param name="decode">Test seam: decodes with the given built-in codec id; only called for an allowed format.</param>
    internal static ulong? Compute(byte[]? imageBytes, Func<Guid, byte[], ulong?> decode) =>
        imageBytes is { Length: > 0 } && CodecFor(imageBytes) is { } codec ? decode(codec, imageBytes) : null;

    /// <summary>The built-in decoder for the format the first bytes announce, or null for any other format.</summary>
    internal static Guid? CodecFor(ReadOnlySpan<byte> b)
    {
        if (b.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xD8, 0xFF])) return BitmapDecoder.JpegDecoderId;
        if (b.StartsWith((ReadOnlySpan<byte>)[0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A])) return BitmapDecoder.PngDecoderId;
        if (b.StartsWith("GIF87a"u8) || b.StartsWith("GIF89a"u8)) return BitmapDecoder.GifDecoderId;
        if (b.StartsWith("BM"u8) && b.Length >= 26) return BitmapDecoder.BmpDecoderId;
        return null;
    }

    static ulong? Decode(Guid codec, byte[] imageBytes)
    {
        try
        {
            using var stream = new InMemoryRandomAccessStream();
            stream.WriteAsync(imageBytes.AsBuffer()).AsTask().GetAwaiter().GetResult();
            stream.Seek(0);

            var decoder = BitmapDecoder.CreateAsync(codec, stream).AsTask().GetAwaiter().GetResult();
            var transform = new BitmapTransform
            {
                ScaledWidth = Width,
                ScaledHeight = Height,
                InterpolationMode = BitmapInterpolationMode.Fant,
            };
            var pixels = decoder.GetPixelDataAsync(
                    BitmapPixelFormat.Bgra8, BitmapAlphaMode.Ignore, transform,
                    ExifOrientationMode.IgnoreExifOrientation, ColorManagementMode.DoNotColorManage)
                .AsTask().GetAwaiter().GetResult();
            var bgra = pixels.DetachPixelData();
            if (bgra.Length < Width * Height * 4) return null;
            return FromBgra(bgra);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Number of differing bits (0 = same picture, small = near duplicate).</summary>
    public static int Distance(ulong a, ulong b) => BitOperations.PopCount(a ^ b);

    /// <summary>
    /// Groups items whose hashes are within <paramref name="maxDistance"/> of each other (transitively).
    /// Returns a group id per key; ids are 0..n-1 in order of first appearance, and an item with no
    /// similar partner gets a group of its own. Duplicate keys keep the last group.
    /// </summary>
    public static IReadOnlyDictionary<string, int> Group(IEnumerable<(string Key, ulong Hash)> items, int maxDistance = 10)
    {
        var list = items.ToList();
        var parent = new int[list.Count];
        for (int i = 0; i < parent.Length; i++) parent[i] = i;

        if (list.Count <= BruteForceLimit || maxDistance >= 63)
        {
            for (int i = 0; i < list.Count; i++)
                for (int j = i + 1; j < list.Count; j++)
                    if (Distance(list[i].Hash, list[j].Hash) <= maxDistance) Union(parent, i, j);
        }
        else
        {
            GroupByBands(list, parent, maxDistance);
        }

        var ids = new Dictionary<int, int>();
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < list.Count; i++)
        {
            int root = Find(parent, i);
            if (!ids.TryGetValue(root, out var id)) ids[root] = id = ids.Count;
            result[list[i].Key] = id;
        }
        return result;
    }

    internal static ulong FromBgra(ReadOnlySpan<byte> bgra)
    {
        ulong hash = 0;
        int bit = 0;
        for (int y = 0; y < Height; y++)
        {
            for (int x = 0; x < Width - 1; x++)
            {
                if (Luma(bgra, y * Width + x) > Luma(bgra, y * Width + x + 1)) hash |= 1UL << bit;
                bit++;
            }
        }
        return hash;
    }

    private static int Luma(ReadOnlySpan<byte> bgra, int pixel)
    {
        int o = pixel * 4;
        return bgra[o] * 114 + bgra[o + 1] * 587 + bgra[o + 2] * 299; // B, G, R (ITU-R 601 weights x1000)
    }

    /// <summary>
    /// Large sets: split the 64 bits into maxDistance+1 bands. Two hashes within maxDistance must agree
    /// exactly on at least one band (pigeonhole), so only items sharing a band value are compared.
    /// </summary>
    private static void GroupByBands(List<(string Key, ulong Hash)> list, int[] parent, int maxDistance)
    {
        int bands = Math.Max(1, maxDistance + 1);
        for (int band = 0; band < bands; band++)
        {
            int start = band * 64 / bands, end = (band + 1) * 64 / bands;
            int width = end - start;
            ulong mask = width >= 64 ? ulong.MaxValue : ((1UL << width) - 1) << start;

            var buckets = new Dictionary<ulong, List<int>>();
            for (int i = 0; i < list.Count; i++)
            {
                var k = list[i].Hash & mask;
                if (!buckets.TryGetValue(k, out var bucket)) buckets[k] = bucket = [];
                bucket.Add(i);
            }
            foreach (var bucket in buckets.Values)
                for (int a = 0; a < bucket.Count; a++)
                    for (int b = a + 1; b < bucket.Count; b++)
                    {
                        int i = bucket[a], j = bucket[b];
                        if (Find(parent, i) != Find(parent, j) && Distance(list[i].Hash, list[j].Hash) <= maxDistance)
                            Union(parent, i, j);
                    }
        }
    }

    private static int Find(int[] parent, int i)
    {
        while (parent[i] != i)
        {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        return i;
    }

    private static void Union(int[] parent, int a, int b)
    {
        int ra = Find(parent, a), rb = Find(parent, b);
        if (ra != rb) parent[Math.Max(ra, rb)] = Math.Min(ra, rb);
    }
}
