using PCPorter.Core.Security;
using PCPorter.Reports;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// Warnings about where the case was saved (for example an exFAT or FAT32 drive: no file permissions, so anyone with the
/// drive can read the case). They matter to the person right away, so the pages put them in the result bar and the
/// commands print them (stderr, and <c>folderWarnings</c> in the JSON).
/// </summary>
public static class FolderWarnings
{
    /// <summary>
    /// The scan result has no separate list: <c>ScanJob</c> puts the case folder's warnings into <c>Warnings</c> together
    /// with the collectors' ones. They are recognised by the sentence <c>CaseFolder.Create</c> always ends them with.
    /// </summary>
    public static IReadOnlyList<string> Of(ScanJobResult r) =>
        r.Warnings.Where(w => w.Contains("Anyone with the drive can open the case", StringComparison.Ordinal)).ToList();

    /// <summary>The result-bar text: <paramref name="message"/>, then each warning on its own line (redacted).</summary>
    public static string Append(string message, IReadOnlyList<string> warnings) =>
        warnings.Count == 0 ? message : message + "\n\n" + string.Join("\n", warnings.Select(w => "Note: " + Redactor.Redact(w)));
}
