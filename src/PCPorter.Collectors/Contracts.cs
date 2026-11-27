using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors;

/// <summary>Everything a collector may use. Collectors are read-only on the scanned PC.</summary>
public sealed record CollectorContext(
    ISystemSource Source,
    IWmiClient Wmi,
    IProcessRunner Processes,
    ISignatureChecker Signatures,
    string WorkFolder,                         // private, case-local temp folder (protected ACL)
    IList<string> Warnings,
    IProgress<string>? Progress = null,
    bool IncludeDefenderPreferences = false);

/// <summary>A scan result row. ItemKey is stable across scans (used to diff two scans and to keep tags).</summary>
public interface IScanItem
{
    string ItemKey { get; }
}

public enum CollectorStatus { Ok, Partial, Failed, SkippedOffline, Cancelled, TimedOut }

/// <param name="Kind">Table/kind name, e.g. "apps", "av", "persistence", "profile".</param>
public sealed record CollectorOutput(string Kind, IReadOnlyList<IScanItem> Items, IReadOnlyList<string> Notes, CollectorStatus Status = CollectorStatus.Ok);

public interface ICollector
{
    string Name { get; }                       // plain words for the progress UI
    CollectorOutput Run(CollectorContext context, CancellationToken ct);
}

public enum SignatureStatus { Valid, Unsigned, Invalid, NotChecked, FileMissing }

public sealed record SignatureInfo(SignatureStatus Status, string? Signer, bool IsMicrosoft, bool ViaCatalog = false);

/// <summary>Authenticode verification (embedded and catalog). Implementations must never touch the network.</summary>
public interface ISignatureChecker
{
    SignatureInfo Check(string path);
}

/// <summary>Used where signatures are not needed (tests, offline without catalogs).</summary>
public sealed class NoSignatureChecker : ISignatureChecker
{
    public SignatureInfo Check(string path) => new(File.Exists(path) ? SignatureStatus.NotChecked : SignatureStatus.FileMissing, null, false);
}
