using System.Buffers.Binary;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// LZ4 block decoder (no frame format), with every length and offset checked against both buffers, plus Firefox's
/// mozLz4 wrapper ("mozLz40\0", uint32 decompressed size, one LZ4 block). Damaged input throws
/// <see cref="InvalidDataException"/>; it never reads or writes outside the buffers.
/// </summary>
public static class Lz4Block
{
    static ReadOnlySpan<byte> MozMagic => "mozLz40\0"u8;

    /// <summary>Decodes one LZ4 block whose decompressed size is exactly <paramref name="size"/> bytes.</summary>
    public static byte[] Decode(ReadOnlySpan<byte> src, int size)
    {
        if (size < 0) throw Bad("has a negative size");
        var dst = new byte[size];
        int s = 0, d = 0;
        while (true)
        {
            if (s >= src.Length) throw Bad("ends before its last sequence");
            int token = src[s++];
            int literals = token >> 4;
            if (literals == 15) literals = ExtendedLength(src, ref s, literals);
            if (literals > src.Length - s) throw Bad("has literals past the end of the input");
            if (literals > size - d) throw Bad("is larger than its declared size");
            src.Slice(s, literals).CopyTo(dst.AsSpan(d));
            s += literals;
            d += literals;
            if (s == src.Length) break;                       // the last sequence holds literals only

            if (src.Length - s < 2) throw Bad("ends inside a match offset");
            int offset = BinaryPrimitives.ReadUInt16LittleEndian(src[s..]);
            s += 2;
            if (offset == 0 || offset > d) throw Bad("refers to data before its start");
            int match = token & 15;
            if (match == 15) match = ExtendedLength(src, ref s, match);
            match += 4;
            if (match > size - d) throw Bad("is larger than its declared size");
            for (int i = 0; i < match; i++, d++) dst[d] = dst[d - offset];   // byte by byte: matches may overlap
        }
        if (d != size) throw Bad($"is {d} bytes, not the declared {size}");
        return dst;
    }

    /// <summary>Decodes a Firefox .jsonlz4 / .mozlz4 file; refuses files that would expand beyond <paramref name="maxSize"/>.</summary>
    public static byte[] DecodeMozLz4(ReadOnlySpan<byte> file, int maxSize = 256 << 20)
    {
        if (file.Length < 12 || !file[..8].SequenceEqual(MozMagic)) throw Bad("is not a mozLz4 file");
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(file[8..]);
        if (size > (uint)maxSize) throw Bad($"would expand to {size:N0} bytes");
        return Decode(file[12..], (int)size);
    }

    static int ExtendedLength(ReadOnlySpan<byte> src, ref int s, int length)
    {
        byte b;
        do
        {
            if (s >= src.Length) throw Bad("ends inside a length");
            b = src[s++];
            length += b;
            if (length > 1 << 30) throw Bad("has an impossible length");
        } while (b == 255);
        return length;
    }

    static InvalidDataException Bad(string what) => new($"The compressed data {what}.");
}
