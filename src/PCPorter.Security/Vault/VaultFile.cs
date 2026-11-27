using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace PCPorter.Security.Vault;

/// <summary>
/// Passphrase-encrypted file format for credentials and other secrets.
/// Layout: header (magic, version, Argon2id params, salt, nonce prefix), then chunks of
/// [4-byte length][ciphertext][16-byte tag]. Each chunk's associated data binds the header,
/// the chunk index and a "final" flag, so tampering, reordering or truncation fails to decrypt.
/// A full-size chunk is never final: the stream always ends with a short (possibly empty) chunk.
/// </summary>
public static class VaultFile
{
    const int ChunkSize = 1024 * 1024, TagSize = 16, NonceSize = 12, SaltSize = 16, PrefixSize = 4;
    const byte Version = 1;
    // magic(4) version(1) memoryKiB(4) iterations(4) parallelism(4) salt(16) noncePrefix(4)
    const int SaltOffset = 17, PrefixOffset = SaltOffset + SaltSize, HeaderSize = PrefixOffset + PrefixSize;
    static ReadOnlySpan<byte> Magic => "PCPV"u8;

    public static void Encrypt(Stream input, Stream output, char[] passphrase, KdfParams? kdf = null)
    {
        kdf ??= new KdfParams();
        var header = new byte[HeaderSize];
        Magic.CopyTo(header);
        header[4] = Version;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(5), kdf.MemoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(9), kdf.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(13), kdf.Parallelism);
        RandomNumberGenerator.Fill(header.AsSpan(SaltOffset, SaltSize + PrefixSize));
        output.Write(header);

        var key = DeriveKey(passphrase, header);
        var plain = new byte[ChunkSize];
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            var cipher = new byte[ChunkSize];
            var tag = new byte[TagSize];
            var len = new byte[4];
            for (long index = 0; ; index++)
            {
                int read = ReadFull(input, plain);
                bool final = read < ChunkSize;
                gcm.Encrypt(Nonce(header, index), plain.AsSpan(0, read), cipher.AsSpan(0, read), tag, Aad(header, index, final));
                BinaryPrimitives.WriteInt32LittleEndian(len, read);
                output.Write(len);
                output.Write(cipher, 0, read);
                output.Write(tag);
                if (final) break;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static void Decrypt(Stream input, Stream output, char[] passphrase)
    {
        var header = new byte[HeaderSize];
        if (ReadFull(input, header) != HeaderSize || !header.AsSpan(0, 4).SequenceEqual(Magic) || header[4] != Version)
            throw new InvalidDataException("Not a PCPorter vault file.");
        ValidateKdf(header);

        var key = DeriveKey(passphrase, header);
        var plain = new byte[ChunkSize];
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            var cipher = new byte[ChunkSize];
            var tag = new byte[TagSize];
            var lenBuf = new byte[4];
            for (long index = 0; ; index++)
            {
                if (ReadFull(input, lenBuf) != 4) throw new AuthenticationTagMismatchException("The vault file is truncated.");
                int len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
                if (len is < 0 or > ChunkSize) throw new AuthenticationTagMismatchException("The vault file is corrupt.");
                if (ReadFull(input, cipher.AsSpan(0, len)) != len || ReadFull(input, tag) != TagSize)
                    throw new AuthenticationTagMismatchException("The vault file is truncated.");
                bool final = len < ChunkSize;
                // Throws AuthenticationTagMismatchException on a wrong passphrase or any tampering.
                gcm.Decrypt(Nonce(header, index), cipher.AsSpan(0, len), tag, plain.AsSpan(0, len), Aad(header, index, final));
                output.Write(plain, 0, len);
                if (final) return;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>Rejects absurd KDF values from a corrupt or hostile header before allocating memory for them.</summary>
    static void ValidateKdf(byte[] header)
    {
        int mem = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(5));
        int iter = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(9));
        int par = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(13));
        if (mem is < 8 * 1024 or > 4 * 1024 * 1024 || iter is < 1 or > 64 || par is < 1 or > 64)
            throw new InvalidDataException("The vault header has invalid key-derivation settings.");
    }

    static byte[] DeriveKey(char[] passphrase, byte[] header)
    {
        var passBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            using var argon = new Argon2id(passBytes)
            {
                Salt = header[SaltOffset..PrefixOffset],
                MemorySize = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(5)),
                Iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(9)),
                DegreeOfParallelism = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(13)),
            };
            return argon.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(passBytes); }
    }

    static byte[] Nonce(byte[] header, long index)
    {
        var nonce = new byte[NonceSize];
        header.AsSpan(PrefixOffset, PrefixSize).CopyTo(nonce);
        BinaryPrimitives.WriteInt64LittleEndian(nonce.AsSpan(PrefixSize), index);
        return nonce;
    }

    static byte[] Aad(byte[] header, long index, bool final)
    {
        var aad = new byte[HeaderSize + 9];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(HeaderSize), index);
        aad[^1] = final ? (byte)1 : (byte)0;
        return aad;
    }

    static int ReadFull(Stream s, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = s.Read(buffer[total..]);
            if (n == 0) break;
            total += n;
        }
        return total;
    }
}
