using PCPorter.Collectors.Signing;

namespace PCPorter.Collectors.Tests.Signing;

public class HResultMapperTests
{
    [Theory]
    [InlineData(0x00000000u, TrustOutcome.Valid)]
    [InlineData(0x800B0100u, TrustOutcome.NotEmbedded)]   // TRUST_E_NOSIGNATURE
    [InlineData(0x800B0003u, TrustOutcome.NotEmbedded)]   // TRUST_E_SUBJECT_FORM_UNKNOWN
    [InlineData(0x800B0001u, TrustOutcome.NotEmbedded)]   // TRUST_E_PROVIDER_UNKNOWN
    [InlineData(0x80096010u, TrustOutcome.Invalid)]       // TRUST_E_BAD_DIGEST
    [InlineData(0x800B0109u, TrustOutcome.Invalid)]       // CERT_E_UNTRUSTEDROOT
    [InlineData(0x800B010Cu, TrustOutcome.Invalid)]       // CERT_E_REVOKED
    [InlineData(0x80092010u, TrustOutcome.Invalid)]       // CRYPT_E_REVOKED
    [InlineData(0x800B0111u, TrustOutcome.Invalid)]       // TRUST_E_EXPLICIT_DISTRUST
    [InlineData(0x800B0101u, TrustOutcome.Invalid)]       // CERT_E_EXPIRED
    [InlineData(0x80092026u, TrustOutcome.Invalid)]       // CRYPT_E_SECURITY_SETTINGS
    [InlineData(0x800B0004u, TrustOutcome.Invalid)]       // TRUST_E_SUBJECT_NOT_TRUSTED
    [InlineData(0x800B010Au, TrustOutcome.Invalid)]       // CERT_E_CHAINING
    [InlineData(0x80096004u, TrustOutcome.Invalid)]       // TRUST_E_CERT_SIGNATURE
    [InlineData(0x80092003u, TrustOutcome.Unknown)]       // CRYPT_E_FILE_ERROR
    [InlineData(0x80004005u, TrustOutcome.Unknown)]       // E_FAIL
    public void Maps_hresults(uint hr, TrustOutcome expected) => Assert.Equal(expected, HResultMapper.Map(unchecked((int)hr)));
}

/// <summary>Windows integration tests against this PC's real files and catalog database (no admin needed).</summary>
public sealed class AuthenticodeCheckerTests : IDisposable
{
    readonly AuthenticodeChecker _checker = new();
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-sig").FullName;

    public void Dispose()
    {
        _checker.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    static string Notepad => Path.Combine(Environment.SystemDirectory, "notepad.exe");

    static IEnumerable<string> System32Binaries(string pattern) =>
        Directory.EnumerateFiles(Environment.SystemDirectory, pattern, new EnumerationOptions { IgnoreInaccessible = true })
            .Order(StringComparer.OrdinalIgnoreCase);

    internal static string FindCatalogOnlyBinary() =>
        System32Binaries("*.dll").Take(400).FirstOrDefault(f => AuthenticodeChecker.EmbeddedHResult(f) == HResultMapper.TRUST_E_NOSIGNATURE)
        ?? throw new InvalidOperationException("No catalog-signed System32 DLL found.");

    static string FindEmbeddedSignedExe() =>
        System32Binaries("*.exe")
            .Where(f => new FileInfo(f).Length is > 100_000 and < 8_000_000)
            .Take(300)
            .FirstOrDefault(f => AuthenticodeChecker.EmbeddedHResult(f) == HResultMapper.S_OK)
        ?? throw new InvalidOperationException("No embedded-signed System32 exe found.");

    [Fact]
    public void Notepad_is_valid_and_microsoft()
    {
        var info = _checker.Check(Notepad);
        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.True(info.IsMicrosoft);
        Assert.Contains("Microsoft", info.Signer);
        bool embedded = AuthenticodeChecker.EmbeddedHResult(Notepad) == HResultMapper.S_OK;
        Assert.Equal(!embedded, info.ViaCatalog);
    }

    [Fact]
    public void Catalog_only_system32_binary_is_valid_via_catalog()
    {
        var file = FindCatalogOnlyBinary();
        var info = _checker.Check(file);
        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.True(info.ViaCatalog);
        Assert.True(info.IsMicrosoft, $"{file}: signer {info.Signer}");
        Assert.NotEmpty(AuthenticodeChecker.CatalogsContaining(file));
    }

    [Fact]
    public void Unsigned_temp_file_is_unsigned()
    {
        var file = Path.Combine(_dir, "unsigned.txt");
        File.WriteAllText(file, "not signed " + Guid.NewGuid());
        var info = _checker.Check(file);
        Assert.Equal(SignatureStatus.Unsigned, info.Status);
        Assert.False(info.IsMicrosoft);
        Assert.Null(info.Signer);
    }

    [Fact]
    public void Signed_copy_with_one_flipped_byte_is_invalid()
    {
        var source = FindEmbeddedSignedExe();
        var copy = Path.Combine(_dir, "tampered.exe");
        File.Copy(source, copy);
        Assert.Equal(SignatureStatus.Valid, _checker.Check(copy).Status);

        var bytes = File.ReadAllBytes(copy);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(copy, bytes);
        File.SetLastWriteTimeUtc(copy, DateTime.UtcNow.AddMinutes(1));

        var info = _checker.Check(copy);
        Assert.Equal(SignatureStatus.Invalid, info.Status);
        Assert.False(info.IsMicrosoft);
        Assert.False(info.ViaCatalog);
    }

    [Fact]
    public void Missing_file_is_file_missing() =>
        Assert.Equal(SignatureStatus.FileMissing, _checker.Check(Path.Combine(_dir, "nope.exe")).Status);

    [Fact]
    public void Results_are_cached_by_path_size_and_mtime()
    {
        var file = Path.Combine(_dir, "cache.txt");
        File.WriteAllText(file, "x" + Guid.NewGuid());
        var first = _checker.Check(file);
        var second = _checker.Check(file.ToUpperInvariant());
        Assert.Same(first, second);
        Assert.Equal(1, _checker.Verifications);

        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddHours(-1));
        _checker.Check(file);
        Assert.Equal(2, _checker.Verifications);
    }

    [Fact]
    public void Parallel_checks_agree()
    {
        var files = new[] { Notepad, FindCatalogOnlyBinary(), Path.Combine(Environment.SystemDirectory, "cmd.exe") };
        using var fresh = new AuthenticodeChecker();
        var expected = files.Select(f => _checker.Check(f).Status).ToArray();
        var results = new SignatureStatus[files.Length * 8];
        Parallel.For(0, results.Length, i => results[i] = fresh.Check(files[i % files.Length]).Status);
        for (int i = 0; i < results.Length; i++) Assert.Equal(expected[i % files.Length], results[i]);
        Assert.All(results, s => Assert.Equal(SignatureStatus.Valid, s));
    }
}

/// <summary>Offline catalogs: a fake drive root holding only the catalogs of one catalog-signed binary.</summary>
public sealed class OfflineCatalogTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-offcat").FullName + "\\";
    readonly string _work = Directory.CreateTempSubdirectory("pcporter-offcat-work").FullName;

    public void Dispose()
    {
        foreach (var d in new[] { _root, _work })
            try { Directory.Delete(d, true); } catch (IOException) { }
    }

    [Fact]
    public void Catalog_signed_file_is_valid_from_the_offline_catalogs_and_others_are_not_checked()
    {
        var file = AuthenticodeCheckerTests.FindCatalogOnlyBinary();
        var catFolder = Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "CatRoot", OfflineCatalogIndex.CatRootGuid)).FullName;
        foreach (var cat in AuthenticodeChecker.CatalogsContaining(file).Distinct(StringComparer.OrdinalIgnoreCase))
            File.Copy(cat, Path.Combine(catFolder, Path.GetFileName(cat)), overwrite: true);
        var catalogBytesBefore = Directory.GetFiles(catFolder).ToDictionary(f => f, File.ReadAllBytes);

        using var index = new OfflineCatalogIndex(_root, _work);
        using var checker = new AuthenticodeChecker(index);

        var info = checker.Check(file);
        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.True(info.ViaCatalog);
        Assert.True(info.IsMicrosoft);
        Assert.True(index.CatalogCount >= 1);
        Assert.True(index.MemberCount > 0);

        var other = Path.Combine(_work, "plain.txt");
        File.WriteAllText(other, "x" + Guid.NewGuid());
        Assert.Equal(SignatureStatus.Unsigned, checker.Check(other).Status);   // catalogs were read: not in any = unsigned

        // the scanned drive's catalogs are never opened for writing or changed
        foreach (var (f, bytes) in catalogBytesBefore) Assert.Equal(bytes, File.ReadAllBytes(f));
    }

    [Fact]
    public void Mostly_damaged_catalogs_mean_not_checked_rather_than_unsigned()
    {
        var file = AuthenticodeCheckerTests.FindCatalogOnlyBinary();
        var catFolder = Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "CatRoot", OfflineCatalogIndex.CatRootGuid)).FullName;
        var good = AuthenticodeChecker.CatalogsContaining(file).First();
        File.Copy(good, Path.Combine(catFolder, Path.GetFileName(good)));
        for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(catFolder, $"broken{i}.cat"), "not a catalog");

        using var index = new OfflineCatalogIndex(_root, _work);
        using var checker = new AuthenticodeChecker(index);
        var other = Path.Combine(_work, "plain.txt");
        File.WriteAllText(other, "x" + Guid.NewGuid());

        Assert.Equal(SignatureStatus.Valid, checker.Check(file).Status);       // what could be read still counts
        Assert.False(index.Trustworthy);
        Assert.Equal(SignatureStatus.NotChecked, checker.Check(other).Status);
    }

    [Fact]
    public void No_catalog_folder_means_not_checked_with_a_note()
    {
        using var index = new OfflineCatalogIndex(_root, _work);
        using var checker = new AuthenticodeChecker(index);
        Assert.Equal(SignatureStatus.NotChecked, checker.Check(AuthenticodeCheckerTests.FindCatalogOnlyBinary()).Status);
        Assert.Equal(0, index.CatalogCount);
        Assert.NotEmpty(index.Notes);
    }
}
