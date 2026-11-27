namespace PCPorter.Core.Config;

public sealed record AppSettings
{
    public int SchemaVersion { get; init; } = 1;
    public bool FirstRunCompleted { get; init; }
    public string Theme { get; init; } = "System";
    public bool CheckForUpdates { get; init; }
    public List<string> RecentCases { get; init; } = [];
}
