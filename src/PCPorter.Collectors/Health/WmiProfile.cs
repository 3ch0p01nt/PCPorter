using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Health;

/// <summary>
/// PC profile facts from WMI (live only). Every query has a timeout; access denied => "unknown (not elevated)",
/// never "absent". Read-only: only SELECTs, never methods (in particular never GetKeyProtectorNumericalPassword).
/// </summary>
public static class WmiProfile
{
    public const string Cimv2 = @"root\cimv2";
    public const string StorageNs = @"root\Microsoft\Windows\Storage";
    public const string TpmNs = @"root\cimv2\Security\MicrosoftTpm";
    public const string BitLockerNs = @"root\cimv2\Security\MicrosoftVolumeEncryption";
    public const string WmiNs = @"root\wmi";
    public static readonly TimeSpan LongTimeout = TimeSpan.FromSeconds(45);

    public const string ActivationQuery =
        "SELECT LicenseStatus, ProductKeyChannel FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL";

    sealed class Ctx(IWmiClient wmi, IList<string> warnings, Dictionary<string, string> unknown)
    {
        public Dictionary<string, string> Unknown => unknown;

        /// <summary>Rows, or null (and the reason recorded) when the query did not succeed.</summary>
        public IReadOnlyList<IReadOnlyDictionary<string, object?>>? Q(string ns, string wql, string field, TimeSpan? timeout = null)
        {
            WmiResult r;
            try { r = wmi.Query(ns, wql, timeout); }
            catch (Exception e) { warnings.Add($"Profile: {field}: WMI failed: {e.Message}"); return null; }
            switch (r.Outcome)
            {
                case WmiOutcome.Ok: return r.Rows;
                case WmiOutcome.AccessDenied: unknown[field] = PcProfile.NotElevated; return null;
                default: warnings.Add($"Profile: {field}: WMI {r.Outcome}{(r.Message is null ? "" : " - " + r.Message)}"); return null;
            }
        }
    }

    public static PcProfile Apply(PcProfile p, IWmiClient wmi, IList<string> warnings)
    {
        var unknown = new Dictionary<string, string>(p.Unknown, StringComparer.OrdinalIgnoreCase);
        var c = new Ctx(wmi, warnings, unknown);
        p = Guard(p, warnings, "processor", () => Processor(p, c));
        p = Guard(p, warnings, "computer", () => ComputerSystem(p, c));
        p = Guard(p, warnings, "video", () => p with { VideoControllers = Video(c) });
        p = Guard(p, warnings, "logical disks", () => p with { LogicalDisks = LogicalDisks(c) });
        p = Guard(p, warnings, "physical disks", () => p with { PhysicalDisks = PhysicalDisks(c) });
        p = Guard(p, warnings, "tpm", () => Tpm(p, c));
        p = Guard(p, warnings, "bitlocker", () => p with { BitLocker = BitLocker(c) });
        p = Guard(p, warnings, "activation", () => Activation(p, c));
        p = Guard(p, warnings, "devices", () => p with { ProblemDevices = Devices(c) });
        p = Guard(p, warnings, "stability", () => Stability(p, c));
        return p with { Unknown = unknown };
    }

    static PcProfile Guard(PcProfile p, IList<string> warnings, string what, Func<PcProfile> f)
    {
        try { return f(); }
        catch (Exception e) { warnings.Add($"Profile: {what} failed: {e.Message}"); return p; }
    }

    static int? Int(IReadOnlyDictionary<string, object?> row, string name) => WmiValue.Long(row, name) is { } n and >= int.MinValue and <= int.MaxValue ? (int)n : null;

    static PcProfile Processor(PcProfile p, Ctx c)
    {
        var rows = c.Q(Cimv2, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", "processor");
        if (rows is null || rows.Count == 0) return p;
        return p with
        {
            Processor = WmiValue.Str(rows[0], "Name"),
            Cores = rows.Sum(r => Int(r, "NumberOfCores") ?? 0) is var n && n > 0 ? n : null,
            LogicalProcessors = rows.Sum(r => Int(r, "NumberOfLogicalProcessors") ?? 0) is var l && l > 0 ? l : null,
        };
    }

    static PcProfile ComputerSystem(PcProfile p, Ctx c)
    {
        var rows = c.Q(Cimv2, "SELECT TotalPhysicalMemory, Manufacturer, Model, PartOfDomain FROM Win32_ComputerSystem", "computer");
        if (rows is null || rows.Count == 0) return p;
        var r = rows[0];
        return p with
        {
            RamBytes = WmiValue.Long(r, "TotalPhysicalMemory"),
            Manufacturer = WmiValue.Str(r, "Manufacturer"),
            Model = WmiValue.Str(r, "Model"),
            DomainJoined = WmiValue.Bool(r, "PartOfDomain") ?? p.DomainJoined,
        };
    }

    static IReadOnlyList<VideoControllerInfo>? Video(Ctx c) =>
        c.Q(Cimv2, "SELECT Name, DriverVersion FROM Win32_VideoController", "video")?
            .Where(r => WmiValue.Str(r, "Name") is not null)
            .Select(r => new VideoControllerInfo(WmiValue.Str(r, "Name")!, WmiValue.Str(r, "DriverVersion"))).ToList();

    static IReadOnlyList<LogicalDiskInfo>? LogicalDisks(Ctx c) =>
        c.Q(Cimv2, "SELECT DeviceID, Size, FreeSpace, FileSystem FROM Win32_LogicalDisk WHERE DriveType=3", "logicalDisks")?
            .Where(r => WmiValue.Str(r, "DeviceID") is not null)
            .Select(r => new LogicalDiskInfo(WmiValue.Str(r, "DeviceID")!, WmiValue.Long(r, "Size"), WmiValue.Long(r, "FreeSpace"), WmiValue.Str(r, "FileSystem")))
            .ToList();

    public static string? MediaType(long? v) => v switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => null };

    public static string? BusType(long? v) => v switch
    {
        null => null,
        1 => "SCSI", 3 => "ATA", 7 => "USB", 8 => "RAID", 9 => "iSCSI", 10 => "SAS", 11 => "SATA", 12 => "SD", 13 => "MMC",
        15 => "Virtual", 16 => "Storage Spaces", 17 => "NVMe",
        var n => $"bus {n}",
    };

    static string? Health(long? v) => v switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => null };

    /// <summary>MSFT_PhysicalDisk joined with MSFT_StorageReliabilityCounter on DeviceId; missing counters stay null.</summary>
    static IReadOnlyList<PhysicalDiskInfo>? PhysicalDisks(Ctx c)
    {
        var disks = c.Q(StorageNs, "SELECT DeviceId, FriendlyName, MediaType, BusType, Size, HealthStatus FROM MSFT_PhysicalDisk", "physicalDisks");
        if (disks is null) return null;
        var counters = c.Q(StorageNs, "SELECT DeviceId, Wear, Temperature, PowerOnHours FROM MSFT_StorageReliabilityCounter", "diskWear");
        var byId = (counters ?? []).Where(r => WmiValue.Str(r, "DeviceId") is not null)
            .GroupBy(r => WmiValue.Str(r, "DeviceId")!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        return disks.Select(d =>
        {
            var id = WmiValue.Str(d, "DeviceId");
            var rc = id is not null && byId.TryGetValue(id, out var x) ? x : null;
            return new PhysicalDiskInfo(id, WmiValue.Str(d, "FriendlyName"), MediaType(WmiValue.Long(d, "MediaType")), BusType(WmiValue.Long(d, "BusType")),
                WmiValue.Long(d, "Size"), Health(WmiValue.Long(d, "HealthStatus")),
                rc is null ? null : Int(rc, "Wear"), rc is null ? null : Int(rc, "Temperature"), rc is null ? null : WmiValue.Long(rc, "PowerOnHours"));
        }).ToList();
    }

    /// <summary>"2.0, 0, 1.59" => "2.0".</summary>
    public static string? TpmVersion(string? specVersion)
    {
        if (string.IsNullOrWhiteSpace(specVersion)) return null;
        var first = specVersion.Split(',', 2)[0].Trim();
        return first.Length == 0 ? null : first;
    }

    static PcProfile Tpm(PcProfile p, Ctx c)
    {
        var rows = c.Q(TpmNs, "SELECT SpecVersion, IsEnabled_InitialValue FROM Win32_Tpm", "tpm");
        if (rows is null) return p;
        if (rows.Count == 0) return p with { TpmPresent = false };
        return p with { TpmPresent = true, TpmVersion = TpmVersion(WmiValue.Str(rows[0], "SpecVersion")) };
    }

    static IReadOnlyList<BitLockerVolume>? BitLocker(Ctx c) =>
        c.Q(BitLockerNs, "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume", "bitlocker")?
            .Select(r => new BitLockerVolume(WmiValue.Str(r, "DriveLetter") ?? "(no letter)",
                WmiValue.Long(r, "ProtectionStatus") switch { 1 => "on", 0 => "off", _ => "unknown" }))
            .ToList();

    static PcProfile Activation(PcProfile p, Ctx c)
    {
        var rows = c.Q(Cimv2, ActivationQuery, "activation", LongTimeout);
        if (rows is null) return p;
        var active = rows.FirstOrDefault(r => WmiValue.Long(r, "LicenseStatus") == 1);
        return p with { Activated = active is not null, ActivationChannel = WmiValue.Str(active ?? rows.FirstOrDefault() ?? new Dictionary<string, object?>(), "ProductKeyChannel") };
    }

    static IReadOnlyList<ProblemDevice>? Devices(Ctx c) =>
        c.Q(Cimv2, "SELECT Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0", "devices")?
            .Select(r => new ProblemDevice(WmiValue.Str(r, "Name") ?? "(unnamed device)", Int(r, "ConfigManagerErrorCode") ?? -1))
            .ToList();

    static PcProfile Stability(PcProfile p, Ctx c)
    {
        var rows = c.Q(Cimv2, "SELECT SystemStabilityIndex, TimeGenerated FROM Win32_ReliabilityStabilityMetrics", "stability", LongTimeout);
        if (rows is null || rows.Count == 0) return p;
        var newest = rows.Select(r => (Row: r, Time: WmiValue.Time(r, "TimeGenerated"))).OrderByDescending(x => x.Time ?? DateTimeOffset.MinValue).First();
        return p with { StabilityIndex = WmiValue.Double(newest.Row, "SystemStabilityIndex"), StabilityTime = newest.Time };
    }

    /// <summary>Joins display-API monitors with WmiMonitorID (make/serial only) on the device instance path.</summary>
    public static IReadOnlyList<MonitorInfo> Monitors(IReadOnlyList<NativeMonitor> native, IWmiClient wmi, IList<string> warnings)
    {
        var ids = new Dictionary<string, (string? Make, string? Serial, string? Name)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var r = wmi.Query(WmiNs, "SELECT InstanceName, ManufacturerName, SerialNumberID, UserFriendlyName FROM WmiMonitorID");
            if (r.Outcome == WmiOutcome.Ok)
                foreach (var row in r.Rows)
                    if (WmiValue.Str(row, "InstanceName") is { } inst)
                        ids[NormalizeInstance(inst)] = (Chars(row, "ManufacturerName"), Chars(row, "SerialNumberID"), Chars(row, "UserFriendlyName"));
        }
        catch (Exception e) { warnings.Add($"Profile: monitor ids failed: {e.Message}"); }

        var list = native.Select(m =>
        {
            var key = m.DevicePath is null ? null : NormalizeDevicePath(m.DevicePath);
            var id = key is not null && ids.TryGetValue(key, out var v) ? v : default;
            return new MonitorInfo(m.FriendlyName ?? id.Name, m.Width, m.Height, m.ScalePercent, id.Make, id.Serial);
        }).ToList();
        if (list.Count == 0)   // display APIs unavailable: still report what WMI knows
            list.AddRange(ids.Values.Select(v => new MonitorInfo(v.Name, null, null, null, v.Make, v.Serial)));
        return list;
    }

    static string? Chars(IReadOnlyDictionary<string, object?> row, string name) => WmiValue.Get(row, name) switch
    {
        ushort[] u => WmiValue.Chars(u),
        IEnumerable<ushort> e => WmiValue.Chars(e),
        string s => WmiValue.Chars(s.Select(ch => (ushort)ch)),
        _ => null,
    };

    /// <summary>"DISPLAY\DEL4321\5&amp;abc&amp;0&amp;UID4352_0" => "DISPLAY\DEL4321\5&amp;abc&amp;0&amp;UID4352".</summary>
    public static string NormalizeInstance(string instanceName)
    {
        var s = instanceName.Trim();
        var us = s.LastIndexOf('_');
        return us > s.LastIndexOf('\\') && us >= 0 ? s[..us] : s;
    }

    /// <summary>"\\?\DISPLAY#DEL4321#5&amp;abc&amp;0&amp;UID4352#{guid}" => "DISPLAY\DEL4321\5&amp;abc&amp;0&amp;UID4352".</summary>
    public static string NormalizeDevicePath(string devicePath)
    {
        var s = devicePath.Trim();
        if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s[4..];
        var parts = s.Split('#');
        if (parts.Length > 1 && parts[^1].StartsWith('{')) parts = parts[..^1];
        return string.Join('\\', parts);
    }
}
