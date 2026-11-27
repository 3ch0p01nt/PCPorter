namespace PCPorter.Core.Config;

public sealed record AppSettings
{
    public int SchemaVersion { get; init; } = 1;
    public bool FirstRunCompleted { get; init; }
    public string Theme { get; init; } = "System";
    public bool CheckForUpdates { get; init; }
    public List<string> RecentCases { get; init; } = [];
    /// <summary>Per-page inputs and last result, keyed by page ("scan", "history", "thumbs"). Added without a schema
    /// bump: older files simply have no "Pages" and load with an empty dictionary.</summary>
    public Dictionary<string, PageMemory> Pages { get; init; } = [];
}
