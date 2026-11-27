namespace PCPorter.Collectors.Health;

public sealed record GpuInfo(string Name, long? VramBytes);
public sealed record VideoControllerInfo(string Name, string? DriverVersion);
public sealed record LogicalDiskInfo(string Drive, long? SizeBytes, long? FreeBytes, string? FileSystem);

/// <param name="MediaType">HDD, SSD or null (unspecified).</param>
/// <param name="BusType">USB, SATA, NVMe, SAS, RAID... or the raw number.</param>
/// <param name="WearPercent">Percent of rated life used; null when the drive does not report it (never 0 for unknown).</param>
public sealed record PhysicalDiskInfo(string? DeviceId, string? Name, string? MediaType, string? BusType, long? SizeBytes, string? Health,
    int? WearPercent, int? TemperatureC, long? PowerOnHours);

/// <param name="Protection">"on", "off" or "unknown".</param>
public sealed record BitLockerVolume(string Drive, string Protection);
public sealed record ProblemDevice(string Name, int ErrorCode);
public sealed record MonitorInfo(string? FriendlyName, int? Width, int? Height, int? ScalePercent, string? Make, string? Serial);

/// <param name="HealthPercent">Full-charge / design capacity, clamped to 100.</param>
public sealed record BatteryInfo(string? Name, string? Manufacturer, string? Chemistry, long? DesignCapacityMWh, long? FullChargeCapacityMWh,
    int? CycleCount, int? HealthPercent);

public sealed record CrashEvent(DateTimeOffset When, string? BugCheck);

/// <param name="UnexpectedShutdowns">Kernel-Power 41 events in the last 90 days (null = log unreadable).</param>
public sealed record CrashSummary(IReadOnlyList<CrashEvent> BugChecks, int? UnexpectedShutdowns, int? MinidumpCount, DateTimeOffset? NewestMinidump, string Source)
{
    public int BugChecks90Days => BugChecks.Count;
}

/// <summary>
/// The PC profile: OS, hardware and health. Every field is nullable: null = could not be read.
/// <see cref="Unknown"/> holds a reason per field where the reason matters (e.g. "unknown (not elevated)").
/// </summary>
public sealed record PcProfile : IScanItem
{
    public string ItemKey => "profile";

    // From the hives (both modes)
    public string? OsName { get; init; }
    public string? ProductName { get; init; }
    public string? EditionId { get; init; }
    public bool? IsHomeEdition { get; init; }
    public string? DisplayVersion { get; init; }
    public int? Build { get; init; }
    public int? Ubr { get; init; }
    /// <summary>CurrentVersion\InstallDate: reset by every feature update, so it is the "last feature update".</summary>
    public DateTimeOffset? LastFeatureUpdate { get; init; }
    /// <summary>Oldest SYSTEM\Setup\Source OS key (or the last feature update when there is none).</summary>
    public DateTimeOffset? OriginalInstall { get; init; }
    /// <summary>x64, x86, arm64 (normalised from PROCESSOR_ARCHITECTURE).</summary>
    public string? Architecture { get; init; }
    public string? ComputerName { get; init; }
    public string? MachineGuid { get; init; }
    public bool? SecureBoot { get; init; }
    public bool? RdpEnabled { get; init; }
    public bool? HyperVEnabled { get; init; }
    public bool? DomainJoined { get; init; }
    public bool? EntraJoined { get; init; }
    public IReadOnlyList<GpuInfo>? Gpus { get; init; }

    // From WMI and display APIs (live only)
    public string? Processor { get; init; }
    public int? Cores { get; init; }
    public int? LogicalProcessors { get; init; }
    public long? RamBytes { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public IReadOnlyList<VideoControllerInfo>? VideoControllers { get; init; }
    public IReadOnlyList<LogicalDiskInfo>? LogicalDisks { get; init; }
    public IReadOnlyList<PhysicalDiskInfo>? PhysicalDisks { get; init; }
    public bool? TpmPresent { get; init; }
    /// <summary>First token of Win32_Tpm.SpecVersion, e.g. "2.0".</summary>
    public string? TpmVersion { get; init; }
    public IReadOnlyList<BitLockerVolume>? BitLocker { get; init; }
    public bool? Activated { get; init; }
    public string? ActivationChannel { get; init; }
    public IReadOnlyList<ProblemDevice>? ProblemDevices { get; init; }
    public double? StabilityIndex { get; init; }
    public DateTimeOffset? StabilityTime { get; init; }
    public IReadOnlyList<MonitorInfo>? Monitors { get; init; }

    // Battery (live) and crashes (both modes)
    /// <summary>Null = no battery (desktop) or not readable; see <see cref="Unknown"/>.</summary>
    public IReadOnlyList<BatteryInfo>? Batteries { get; init; }
    public CrashSummary? Crashes { get; init; }

    public IReadOnlyDictionary<string, string> Unknown { get; init; } = new Dictionary<string, string>();

    public const string NotElevated = "unknown (not elevated)";
}
