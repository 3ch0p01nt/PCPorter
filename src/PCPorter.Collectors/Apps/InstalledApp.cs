namespace PCPorter.Collectors.Apps;

public enum AppKind { Win32, Store, Runtime, Driver, Game, Portable }

/// <summary>One installed program found on the scanned PC.</summary>
/// <param name="Architecture">x64 | x86 | arm64 | neutral</param>
/// <param name="Scope">"Machine" or "User:&lt;profile folder name&gt;"</param>
/// <param name="MatchMethod">How WingetId was found: InstalledByWinget (winget's own records) | ProductCode (product, upgrade or package family code) | NameMatch | ExportFallback | None (null = matching did not run).</param>
/// <param name="SourceKey">Where the entry came from (registry key path, "steam:&lt;appid&gt;", "choco:&lt;id&gt;", ...).</param>
public sealed record InstalledApp(
    string ItemKey, string Name, string? Version, string? Publisher, string Architecture,
    DateOnly? InstallDate, bool InstallDateInferred, string Scope,
    AppKind Kind, bool Hidden, bool ReinstallCandidate,
    string? ProductCode, string? UpgradeCode, bool WindowsInstaller, string? InstallLocation,
    string? UninstallString, string? QuietUninstallString, string? HelpLink, string? UrlInfoAbout,
    string? WingetId, string? WingetSource, string? ChocoId, string? ScoopId, string? PackageFamilyName,
    string? MatchMethod, string SourceKey) : IScanItem
{
    /// <summary>Stable key: lower(normalized name) | publisher | scope | arch.</summary>
    public static string KeyFor(string name, string? publisher, string scope, string architecture) =>
        $"{AppNameNormalizer.Normalize(name)}|{publisher?.Trim() ?? ""}|{scope}|{architecture}";

    /// <summary>A minimal app (non-registry sources); fill the rest with <c>with</c>.</summary>
    public static InstalledApp Create(string name, string? version, string? publisher, string architecture, string scope,
        AppKind kind, string sourceKey, string? installLocation = null, DateOnly? installDate = null, bool reinstallCandidate = true) =>
        new(KeyFor(name, publisher, scope, architecture), name, version, publisher, architecture, installDate, false, scope,
            kind, false, reinstallCandidate, null, null, false, installLocation, null, null, null, null,
            null, null, null, null, null, null, sourceKey);

    /// <summary>Re-derives ItemKey after Name/Publisher/Scope/Architecture changed.</summary>
    public InstalledApp Rekey() => this with { ItemKey = KeyFor(Name, Publisher, Scope, Architecture) };
}
