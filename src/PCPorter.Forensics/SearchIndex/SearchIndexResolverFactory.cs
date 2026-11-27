using PCPorter.Forensics.Thumbcache;

namespace PCPorter.Forensics.SearchIndex;

/// <summary>Chooses the search index reader for a PC from the files present in its search data folder.</summary>
public static class SearchIndexResolverFactory
{
    const string Windows11FileName = "Windows.db";
    static readonly string ApplicationsSubfolder = Path.Combine("Data", "Applications", "Windows");

    /// <summary>
    /// Picks the Windows 11 (Windows.db, SQLite) reader, else the Windows 10 (Windows.edb, ESE) reader, else one
    /// that only explains why paths are unavailable. <paramref name="programDataSearchFolder"/> may be the
    /// <c>ProgramData\Microsoft\Search</c> folder or the <c>...\Data\Applications\Windows</c> folder itself;
    /// <paramref name="workFolder"/> receives the temporary copy the Windows 10 reader needs.
    /// </summary>
    public static IThumbnailPathResolver ForPc(string programDataSearchFolder, string workFolder, IProgress<string>? progress = null)
    {
        foreach (var folder in new[] { programDataSearchFolder, Path.Combine(programDataSearchFolder, ApplicationsSubfolder) })
        {
            var sqlite = Path.Combine(folder, Windows11FileName);
            if (File.Exists(sqlite)) return new SearchIndexPathResolver(sqlite, progress);
            if (File.Exists(Path.Combine(folder, EseSearchIndexPathResolver.DatabaseFileName)))
                return new EseSearchIndexPathResolver(folder, workFolder, progress);
        }
        return new NoteResolver("No Windows Search index was found (or it is not readable without administrator rights). Original file paths are shown as unknown.");
    }

    sealed class NoteResolver(string note) : IThumbnailPathResolver
    {
        public IReadOnlyDictionary<ulong, string> Resolve(IReadOnlyCollection<ulong> cacheIds) => new Dictionary<ulong, string>();
        public IReadOnlyList<string> Notes => [note];
    }
}
