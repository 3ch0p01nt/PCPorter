using System.Globalization;
using System.Text.Json.Serialization;

namespace PCPorter.Core.Config;

[JsonConverter(typeof(JsonStringEnumConverter<RunOutcome>))]
public enum RunOutcome { Ok, Partial, Stopped, Failed }

/// <summary>The last finished run of a page: what the page showed, plus where its report and case folder are.</summary>
public sealed record LastRun(DateTime FinishedAt, RunOutcome Outcome, string Summary, string? ReportPath, string? CaseFolder);

/// <summary>
/// What one page remembers between app starts: its inputs and its last finished run. Never scan data, only the choices
/// and the one-line result the page already showed.
/// </summary>
public sealed record PageMemory
{
    public string? SaveFolder { get; init; }
    /// <summary>"this-pc" or "other-drive".</summary>
    public string? Source { get; init; }
    /// <summary>Root of the other PC's drive (for example "E:\"); restored only if that drive is still listed.</summary>
    public string? DriveRoot { get; init; }
    /// <summary>Checkbox states by a stable name chosen by the page (for example "allUsers").</summary>
    public Dictionary<string, bool> Options { get; init; } = [];
    public LastRun? LastRun { get; init; }

    public const string ThisPc = "this-pc", OtherDrive = "other-drive";
}

/// <summary>
/// Reads and updates one page's <see cref="PageMemory"/> in the settings file. Settings never crash the UI: read and
/// write errors go to <paramref name="onError"/> and the page carries on with defaults.
/// </summary>
public sealed class PageMemoryStore(SettingsStore store, Action<Exception>? onError = null)
{
    public PageMemory Get(string page)
    {
        try { return Load().Pages?.GetValueOrDefault(page) ?? new PageMemory(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { onError?.Invoke(ex); return new PageMemory(); }
    }

    /// <summary>Applies <paramref name="change"/> to one page's memory and saves; other pages and settings are kept.</summary>
    public void Update(string page, Func<PageMemory, PageMemory> change)
    {
        try
        {
            var settings = Load();
            var pages = new Dictionary<string, PageMemory>(settings.Pages ?? []);
            pages[page] = change(pages.GetValueOrDefault(page) ?? new PageMemory());
            store.Save(settings with { Pages = pages });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { onError?.Invoke(ex); }
    }

    /// <summary>
    /// The last run worth showing: only while its report file still exists. A run whose report is gone (moved, deleted,
    /// or never written) is forgotten so the page does not offer a dead link again.
    /// </summary>
    public LastRun? RecallLastRun(string page, Func<string, bool>? fileExists = null)
    {
        var run = Get(page).LastRun;
        if (run is null) return null;
        if (ShouldShow(run, fileExists ?? File.Exists)) return run;
        Update(page, m => m with { LastRun = null });
        return null;
    }

    public static bool ShouldShow(LastRun run, Func<string, bool> fileExists) =>
        !string.IsNullOrEmpty(run.ReportPath) && fileExists(run.ReportPath);

    /// <summary>"Last check: 27 Nov 2026 14:05 - All parts were checked."</summary>
    public static string Describe(string label, LastRun run) =>
        $"{label}: {run.FinishedAt.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture)} - {run.Summary}";

    AppSettings Load() => store.Load();   // one place to read, so Get and Update see the same file
}
