using System.Security.Cryptography;
using PCPorter.Security.Vault;

namespace PCPorter.Security.Tests.Vault;

public class VaultFileTests
{
    static readonly KdfParams Fast = new(MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1); // tests only
    static byte[] Data(int n) { var b = new byte[n]; Random.Shared.NextBytes(b); return b; }

    static byte[] Encrypt(byte[] plain, string pass)
    {
        using var input = new MemoryStream(plain); using var output = new MemoryStream();
        VaultFile.Encrypt(input, output, pass.ToCharArray(), Fast);
        return output.ToArray();
    }

    static byte[] Decrypt(byte[] cipher, string pass)
    {
        using var input = new MemoryStream(cipher); using var output = new MemoryStream();
        VaultFile.Decrypt(input, output, pass.ToCharArray());
        return output.ToArray();
    }

    [Theory, InlineData(0), InlineData(10), InlineData(1024 * 1024), InlineData(3 * 1024 * 1024 + 7)]
    public void Round_trips(int size)
    {
        var plain = Data(size);
        Assert.Equal(plain, Decrypt(Encrypt(plain, "correct horse battery staple"), "correct horse battery staple"));
    }

    [Fact] public void Same_input_encrypts_differently_each_time() =>
        Assert.NotEqual(Encrypt(new byte[100], "p"), Encrypt(new byte[100], "p"));

    [Fact] public void Wrong_passphrase_fails() =>
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(Encrypt(Data(100), "right"), "wrong"));

    [Fact] public void Flipped_bit_fails()
    {
        var c = Encrypt(Data(5000), "p"); c[^20] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c, "p"));
    }

    [Fact] public void Tampered_header_fails()
    {
        var c = Encrypt(Data(100), "p"); c[30] ^= 1;   // inside the salt
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c, "p"));
    }

    [Fact] public void Truncated_file_fails()
    {
        var c = Encrypt(Data(3 * 1024 * 1024), "p");   // 3 full chunks + empty final chunk
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c[..(c.Length - 30)], "p"));
    }

    [Fact] public void Dropping_the_final_chunk_fails()
    {
        var c = Encrypt(Data(2 * 1024 * 1024), "p");   // final chunk = 4 len + 0 data + 16 tag
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c[..(c.Length - 20)], "p"));
    }

    [Fact] public void Not_a_vault_fails() =>
        Assert.Throws<InvalidDataException>(() => Decrypt("hello world, this is not a vault file at all"u8.ToArray(), "p"));
}
