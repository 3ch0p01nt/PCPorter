using System.Text;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class Lz4BlockTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(269)]
    [InlineData(270)]
    [InlineData(5000)]
    public void Literal_only_blocks_decode(int length)
    {
        var data = Enumerable.Range(0, length).Select(i => (byte)(i * 31 + 7)).ToArray();
        Assert.Equal(data, Lz4Block.Decode(Lz4Test.LiteralBlock(data), data.Length));
    }

    [Fact]
    public void A_match_copies_earlier_output()
    {
        // "abc" + match(offset 3, length 9) + "x"
        byte[] block = [0x35, (byte)'a', (byte)'b', (byte)'c', 3, 0, 0x10, (byte)'x'];
        Assert.Equal("abcabcabcabcx", Encoding.ASCII.GetString(Lz4Block.Decode(block, 13)));
    }

    [Fact]
    public void An_overlapping_match_with_an_extended_length_repeats_a_byte()
    {
        // "a" + match(offset 1, length 39 = 15 + 20 + 4) + "b"
        byte[] block = [0x1F, (byte)'a', 1, 0, 20, 0x10, (byte)'b'];
        Assert.Equal(new string('a', 40) + "b", Encoding.ASCII.GetString(Lz4Block.Decode(block, 41)));
    }

    [Theory]
    [InlineData(new byte[] { }, 0)]                                         // no sequence at all
    [InlineData(new byte[] { 0x50, 1, 2 }, 5)]                               // literals run past the input
    [InlineData(new byte[] { 0x30, 1, 2, 3 }, 2)]                            // output larger than declared
    [InlineData(new byte[] { 0x30, 1, 2, 3 }, 4)]                            // output smaller than declared
    [InlineData(new byte[] { 0x10, 1, 0, 0, 0x10, 2 }, 6)]                   // offset 0
    [InlineData(new byte[] { 0x10, 1, 2, 0, 0x10, 2 }, 6)]                   // offset before the start
    [InlineData(new byte[] { 0x10, 1, 1 }, 6)]                               // input ends inside an offset
    [InlineData(new byte[] { 0x1F, 1, 1, 0 }, 40)]                           // input ends inside a length
    [InlineData(new byte[] { 0x14, 1, 1, 0, 0x10, 2 }, 6)]                   // match larger than declared
    [InlineData(new byte[] { 0x10, 1 }, -1)]                                 // negative size
    public void Damaged_blocks_throw_invalid_data(byte[] block, int size) =>
        Assert.Throws<InvalidDataException>(() => Lz4Block.Decode(block, size));

    [Fact]
    public void MozLz4_files_decode_and_bad_headers_or_sizes_are_refused()
    {
        var json = Encoding.UTF8.GetBytes("{\"windows\":[]}");
        Assert.Equal(json, Lz4Block.DecodeMozLz4(Lz4Test.MozLz4(json)));

        Assert.Throws<InvalidDataException>(() => Lz4Block.DecodeMozLz4("mozLz40"u8));
        Assert.Throws<InvalidDataException>(() => Lz4Block.DecodeMozLz4((byte[])[.. "mozLz41\0"u8, 1, 0, 0, 0, 0x10, 0x41]));
        Assert.Throws<InvalidDataException>(() => Lz4Block.DecodeMozLz4((byte[])[.. "mozLz40\0"u8, 0xFF, 0xFF, 0xFF, 0x7F, 0x10, 0x41], maxSize: 1 << 20));
    }
}
