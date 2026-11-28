using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using static PCPorter.Collectors.Signing.WinTrustNative;

namespace PCPorter.Collectors.Signing;

/// <summary>
/// Authenticode verification: embedded signature first, then the Windows catalog database (this PC) or an
/// <see cref="OfflineCatalogIndex"/> (another PC's drive). Never touches the network: revocation checks are off and
/// URL retrieval is cache-only. Thread-safe; results are cached by (path, size, last write time).
/// </summary>
public sealed class AuthenticodeChecker : ISignatureChecker, IDisposable
{
    const string Sha256 = "SHA256";   // BCRYPT_SHA256_ALGORITHM
    const string Sha1 = "SHA1";       // BCRYPT_SHA1_ALGORITHM
    static readonly string[] HashAlgorithms = [Sha256, Sha1];

    readonly OfflineCatalogIndex? _offline;
    readonly ConcurrentDictionary<(string Path, long Size, DateTime Mtime), SignatureInfo> _cache = new();
    readonly ThreadLocal<CatAdmin> _admins = new(() => new CatAdmin(), trackAllValues: true);
    int _verifications;

    /// <param name="offlineCatalogs">
    /// For a dead PC's drive: catalogs come from that drive's CatRoot instead of this PC's catalog database.
    /// A file without an embedded signature and without a match in the index is <see cref="SignatureStatus.Unsigned"/> when
    /// the drive's catalogs were read, and <see cref="SignatureStatus.NotChecked"/> when none could be read.
    /// </param>
    public AuthenticodeChecker(OfflineCatalogIndex? offlineCatalogs = null) => _offline = offlineCatalogs;

    /// <summary>How many files were actually verified (cache misses).</summary>
    public int Verifications => Volatile.Read(ref _verifications);

    public SignatureInfo Check(string path)
    {
        // A link on the scanned drive is never followed (it may point at a network share): unknown, not "missing".
        switch (SourcePresence.Of(path))
        {
            case Presence.Missing: return new SignatureInfo(SignatureStatus.FileMissing, null, false);
            case Presence.NotFollowed: return new SignatureInfo(SignatureStatus.NotChecked, null, false);
        }
        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists) return new SignatureInfo(SignatureStatus.FileMissing, null, false);
        }
        catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return new SignatureInfo(SignatureStatus.FileMissing, null, false);
        }

        var key = (fi.FullName.ToUpperInvariant(), fi.Length, fi.LastWriteTimeUtc);
        if (_cache.TryGetValue(key, out var hit)) return hit;
        var result = CheckUncached(fi.FullName);
        _cache[key] = result;
        return result;
    }

    SignatureInfo CheckUncached(string path)
    {
        Interlocked.Increment(ref _verifications);
        int hr = EmbeddedHResult(path, out var signer);
        return HResultMapper.Map(hr) switch
        {
            TrustOutcome.Valid => Info(SignatureStatus.Valid, signer, false),
            TrustOutcome.Invalid => Info(SignatureStatus.Invalid, signer, false),
            TrustOutcome.NotEmbedded => _offline is null ? CheckCatalogDatabase(path) : CheckOfflineCatalogs(path, _offline),
            _ => new SignatureInfo(SignatureStatus.NotChecked, null, false),
        };
    }

    static SignatureInfo Info(SignatureStatus status, string? signer, bool viaCatalog) =>
        new(status, signer, status == SignatureStatus.Valid && SignerNames.IsMicrosoft(signer), viaCatalog);

    // ---------------------------------------------------------------- embedded

    /// <summary>The raw WinVerifyTrust result for the file's embedded signature (no catalog lookup).</summary>
    public static int EmbeddedHResult(string path) => EmbeddedHResult(path, out _);

    static int EmbeddedHResult(string path, out string? signer)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pathPtr,
            }, info, false);
            return Verify(WTD_CHOICE_FILE, info, out signer);
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    // ---------------------------------------------------------------- catalogs

    SignatureInfo CheckCatalogDatabase(string path)
    {
        var admin = _admins.Value!;
        bool foundButNotVerified = false;
        foreach (var alg in HashAlgorithms)
        {
            var hCatAdmin = admin.Get(alg);
            if (hCatAdmin == IntPtr.Zero) continue;
            var hash = CalcHash(hCatAdmin, path);
            if (hash is null) continue;
            var tag = Convert.ToHexString(hash);

            IntPtr prev = IntPtr.Zero, catInfo;
            while ((catInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, (uint)hash.Length, 0, ref prev)) != IntPtr.Zero)
            {
                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(), wszCatalogFile = "" };
                if (CryptCATCatalogInfoFromContext(catInfo, ref ci, 0))
                {
                    int hr = VerifyCatalogMember(hCatAdmin, ci.wszCatalogFile, tag, path, hash, out var signer);
                    if (hr == HResultMapper.S_OK)
                    {
                        CryptCATAdminReleaseCatalogContext(hCatAdmin, catInfo, 0);
                        return Info(SignatureStatus.Valid, signer, true);
                    }
                    foundButNotVerified = true;
                }
                prev = catInfo;   // released by the next EnumCatalogFromHash call
            }
        }
        return foundButNotVerified
            ? new SignatureInfo(SignatureStatus.Invalid, null, false, true)
            : new SignatureInfo(SignatureStatus.Unsigned, null, false);
    }

    SignatureInfo CheckOfflineCatalogs(string path, OfflineCatalogIndex index)
    {
        var admin = _admins.Value!;
        bool foundButNotVerified = false;
        foreach (var alg in HashAlgorithms)
        {
            var hCatAdmin = admin.Get(alg);
            if (hCatAdmin == IntPtr.Zero) continue;
            var hash = CalcHash(hCatAdmin, path);
            if (hash is null) continue;
            var tag = Convert.ToHexString(hash);
            foreach (var catalog in index.CatalogsFor(tag))
            {
                int hr = VerifyCatalogMember(hCatAdmin, catalog, tag, path, hash, out var signer);
                if (hr == HResultMapper.S_OK) return Info(SignatureStatus.Valid, signer, true);
                foundButNotVerified = true;
            }
        }
        // Once the old PC's catalogs were read, "in no catalog and no embedded signature" means unsigned, as on a live PC
        // (otherwise unsigned malware on a dead PC's drive would only be "not checked"). Without catalogs we cannot tell.
        if (foundButNotVerified) return new SignatureInfo(SignatureStatus.Invalid, null, false, true);
        return index.Trustworthy
            ? new SignatureInfo(SignatureStatus.Unsigned, null, false)
            : new SignatureInfo(SignatureStatus.NotChecked, null, false);
    }

    /// <summary>Catalog files in this PC's catalog database that list the file (diagnostics and tests).</summary>
    public static IReadOnlyList<string> CatalogsContaining(string path)
    {
        var list = new List<string>();
        using var admin = new CatAdmin();
        foreach (var alg in HashAlgorithms)
        {
            var hCatAdmin = admin.Get(alg);
            if (hCatAdmin == IntPtr.Zero) continue;
            var hash = CalcHash(hCatAdmin, path);
            if (hash is null) continue;
            IntPtr prev = IntPtr.Zero, catInfo;
            while ((catInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, (uint)hash.Length, 0, ref prev)) != IntPtr.Zero)
            {
                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(), wszCatalogFile = "" };
                if (CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) list.Add(ci.wszCatalogFile);
                prev = catInfo;
            }
        }
        return list;
    }

    static byte[]? CalcHash(IntPtr hCatAdmin, string path)
    {
        try
        {
            using SafeFileHandle file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[64];
            uint cb = (uint)buffer.Length;
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file, ref cb, buffer, 0) || cb == 0 || cb > buffer.Length) return null;
            return buffer[..(int)cb];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    static int VerifyCatalogMember(IntPtr hCatAdmin, string catalogFile, string memberTag, string memberPath, byte[] hash, out string? signer)
    {
        var catPtr = Marshal.StringToHGlobalUni(catalogFile);
        var tagPtr = Marshal.StringToHGlobalUni(memberTag);
        var memberPtr = Marshal.StringToHGlobalUni(memberPath);
        var hashPtr = Marshal.AllocHGlobal(hash.Length);
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
        try
        {
            Marshal.Copy(hash, 0, hashPtr, hash.Length);
            Marshal.StructureToPtr(new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = memberPtr,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = hCatAdmin,
            }, info, false);
            return Verify(WTD_CHOICE_CATALOG, info, out signer);
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(hashPtr);
            Marshal.FreeHGlobal(memberPtr);
            Marshal.FreeHGlobal(tagPtr);
            Marshal.FreeHGlobal(catPtr);
        }
    }

    // ---------------------------------------------------------------- WinVerifyTrust core

    static int Verify(uint unionChoice, IntPtr union, out string? signer)
    {
        var action = GenericVerifyV2;
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = union,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = ProvFlags,
        };
        signer = null;
        try
        {
            int hr = WinVerifyTrust(InvalidHandle, ref action, ref data);
            signer = ReadSigner(data.hWVTStateData);
            return hr;
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(InvalidHandle, ref action, ref data);
        }
    }

    static string? ReadSigner(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero) return null;
        var provData = WTHelperProvDataFromStateData(stateData);
        if (provData == IntPtr.Zero) return null;
        var sgnr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (sgnr == IntPtr.Zero) return null;
        var provCert = WTHelperGetProvCertFromChain(sgnr, 0);
        if (provCert == IntPtr.Zero) return null;
        var head = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT_HEAD>(provCert);
        if (head.pCert == IntPtr.Zero) return null;
        var buffer = new char[512];
        uint n = CertGetNameString(head.pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, buffer, (uint)buffer.Length);
        return n <= 1 ? null : new string(buffer, 0, (int)n - 1);
    }

    public void Dispose()
    {
        foreach (var admin in _admins.Values) admin.Dispose();
        _admins.Dispose();
    }

    /// <summary>Catalog admin contexts (SHA-256 and SHA-1) for one thread.</summary>
    sealed class CatAdmin : IDisposable
    {
        readonly Dictionary<string, IntPtr> _handles = new(StringComparer.Ordinal);

        public IntPtr Get(string algorithm)
        {
            if (_handles.TryGetValue(algorithm, out var h)) return h;
            if (!CryptCATAdminAcquireContext2(out h, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) h = IntPtr.Zero;
            _handles[algorithm] = h;
            return h;
        }

        public void Dispose()
        {
            foreach (var h in _handles.Values)
                if (h != IntPtr.Zero) CryptCATAdminReleaseContext(h, 0);
            _handles.Clear();
        }
    }
}
