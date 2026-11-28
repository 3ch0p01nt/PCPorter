using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using PCPorter.Collectors.Sources;
using static PCPorter.Collectors.Signing.WinTrustNative;

namespace PCPorter.Collectors.Signing;

/// <summary>
/// Member hash -> catalog file, built from a dead PC's
/// <c>Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\*.cat</c>.
/// The scanned drive is only read: each catalog is streamed into a private work folder and CryptCATOpen only ever
/// opens that copy. Built lazily on first use; thread-safe.
/// </summary>
public sealed class OfflineCatalogIndex : IDisposable
{
    public const string CatRootGuid = "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";

    readonly string _catalogFolder;
    readonly string _workFolder;
    readonly Lazy<Dictionary<string, List<string>>> _index;
    readonly ConcurrentDictionary<string, string> _copies = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentQueue<string> _notes = new();
    int _copyCounter;

    /// <param name="offlineRoot">Root of the scanned Windows drive, e.g. "D:\".</param>
    /// <param name="workFolder">Private folder on THIS PC for catalog copies; a temp folder when null.</param>
    public OfflineCatalogIndex(string offlineRoot, string? workFolder = null)
    {
        _catalogFolder = Path.Combine(offlineRoot, "Windows", "System32", "CatRoot", CatRootGuid);
        _workFolder = workFolder is null
            ? Directory.CreateTempSubdirectory("pcporter-cat").FullName
            : Directory.CreateDirectory(Path.Combine(workFolder, "catalogs-" + Guid.NewGuid().ToString("N")[..8])).FullName;
        _index = new(Build, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public string CatalogFolder => _catalogFolder;
    int _catalogCount;
    public int CatalogCount { get { _ = _index.Value; return _catalogCount; } }
    public int MemberCount => _index.Value.Count;
    int _failedCount;

    /// <summary>
    /// The catalogs were read well enough to say "in no catalog = unsigned": at least one opened and at most 1 in 10
    /// failed. A damaged CatRoot (likely on a dead PC) would otherwise make catalog-signed Windows files look unsigned.
    /// </summary>
    public bool Trustworthy { get { _ = _index.Value; return _catalogCount > 0 && _failedCount * 10 <= _catalogCount + _failedCount; } }
    public IReadOnlyList<string> Notes => [.. _notes];

    /// <summary>Local copies of the scanned drive's catalogs that list this member tag (uppercase hex hash).</summary>
    public IEnumerable<string> CatalogsFor(string memberTag)
    {
        if (!_index.Value.TryGetValue(memberTag.ToUpperInvariant(), out var catalogs)) yield break;
        foreach (var original in catalogs)
            if (LocalCopy(original) is { } copy) yield return copy;
    }

    Dictionary<string, List<string>> Build()
    {
        var index = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (!SourcePresence.IsFolder(_catalogFolder))   // never through a link (it may point at a network share)
        {
            _notes.Enqueue($"No catalog folder at {_catalogFolder}; files without an embedded signature are not checked.");
            return index;
        }
        int count = 0;
        var scratch = Path.Combine(_workFolder, "scan.cat");
        foreach (var catalog in SourceFiles.Files(_catalogFolder, "*.cat"))
        {
            try { CopyFrom(catalog, scratch); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _notes.Enqueue($"Could not read {Path.GetFileName(catalog)}."); _failedCount++; continue; }

            var hCat = CryptCATOpen(scratch, CRYPTCAT_OPEN_EXISTING, IntPtr.Zero, 0, 0);
            if (hCat == IntPtr.Zero || hCat == InvalidHandle) { _notes.Enqueue($"Could not open {Path.GetFileName(catalog)}."); _failedCount++; continue; }
            try
            {
                count++;
                var member = CryptCATEnumerateMember(hCat, IntPtr.Zero);
                while (member != IntPtr.Zero)
                {
                    var head = Marshal.PtrToStructure<CRYPTCATMEMBER_HEAD>(member);
                    if (Marshal.PtrToStringUni(head.pwszReferenceTag) is { Length: > 0 } tag)
                    {
                        if (!index.TryGetValue(tag, out var list)) index[tag.ToUpperInvariant()] = list = [];
                        if (!list.Contains(catalog, StringComparer.OrdinalIgnoreCase)) list.Add(catalog);
                    }
                    member = CryptCATEnumerateMember(hCat, member);
                }
            }
            finally { CryptCATClose(hCat); }
        }
        try { File.Delete(scratch); } catch (IOException) { }
        _catalogCount = count;
        return index;
    }

    string? LocalCopy(string original)
    {
        if (_copies.TryGetValue(original, out var existing)) return existing;
        var target = Path.Combine(_workFolder, $"{Interlocked.Increment(ref _copyCounter):D5}.cat");
        try { CopyFrom(original, target); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        return _copies.GetOrAdd(original, target);
    }

    static void CopyFrom(string source, string target)
    {
        using var input = SourceFiles.OpenRead(source);
        using var output = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
    }

    public void Dispose()
    {
        try { Directory.Delete(_workFolder, true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
