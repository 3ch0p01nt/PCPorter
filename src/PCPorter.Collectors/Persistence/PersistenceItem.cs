using System.Security.Cryptography;
using System.Text;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

/// <summary>How much a finding is worth a look. Hidden = normal Windows/Microsoft entries, kept but not shown by default.</summary>
public enum Severity { Hidden, Info, Low, Medium, High }

/// <summary>What kind of autostart location an entry came from (drives the location-specific rules).</summary>
public enum EntryKind
{
    Autostart, Service, Task, WmiConsumer, Accessibility, IfeoDebugger, Winlogon, DllInjection, ComHijack, File, BrowserExtension,
}

/// <summary>A raw autostart entry as read from the scanned PC, before signature checks and scoring.</summary>
/// <param name="Location">Where it was found, e.g. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run.</param>
/// <param name="Name">Value, key, task or file name.</param>
/// <param name="Command">The command line (or file path) exactly as the scanned PC stores it.</param>
public sealed record PersistenceEntry(string Location, string Name, string Command, EntryKind Kind = EntryKind.Autostart)
{
    /// <summary>Turned off (StartupApproved, disabled task, inactive monitor...).</summary>
    public bool Disabled { get; init; }
    /// <summary>Scheduled task with no task file or no security descriptor in TaskCache.</summary>
    public bool TaskHidden { get; init; }
    public DateTimeOffset? LastWrite { get; init; }
    /// <summary>Explicit payload (scanned-PC path), e.g. a svchost ServiceDll; overrides the payload parsed from the command.</summary>
    public string? Payload { get; init; }
    /// <summary>Nothing to verify on disk (e.g. a browser extension id).</summary>
    public bool NoFile { get; init; }
    /// <summary>Start of a text script's content (startup-folder scripts, PowerShell profiles), checked for suspicious patterns.</summary>
    public string? ScriptText { get; init; }
    /// <summary>Extra plain-English context appended to the reason.</summary>
    public string? Note { get; init; }
    /// <summary>The user the entry belongs to (for %APPDATA% etc.), null for machine-wide entries.</summary>
    public UserProfile? User { get; init; }
}

/// <summary>A scored autostart finding.</summary>
public sealed record PersistenceItem(
    string Location,
    string Name,
    string Command,
    string? ImagePath,
    string? PayloadPath,
    string? Signer,
    SignatureStatus SignatureStatus,
    Severity Severity,
    string RuleId,
    string Reason,
    bool Disabled,
    DateTimeOffset? LastWrite) : IScanItem
{
    /// <summary>location|name|SHA-256(normalized command): stable across scans.</summary>
    public string ItemKey { get; } = MakeKey(Location, Name, Command);

    /// <summary>Kept in the output but not shown by default.</summary>
    public bool IsHidden => Severity == Severity.Hidden;

    public static string MakeKey(string location, string name, string command)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(NormalizeCommand(command)));
        return $"{location}|{name}|{Convert.ToHexStringLower(hash)}";
    }

    /// <summary>Trimmed, lower-case, whitespace collapsed.</summary>
    public static string NormalizeCommand(string command) =>
        string.Join(' ', (command ?? "").Trim().ToLowerInvariant().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
}
