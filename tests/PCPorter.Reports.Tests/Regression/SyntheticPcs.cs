using PCPorter.Collectors;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Health;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Security;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Made-up PCs for report regression tests. Each is a list of collectors returning fixed items, so the report text is
/// fully determined. Planted details come from real bugs (duplicate app versions, a secret in a command line, a
/// device turned off on purpose, an "informational" setting that says no action is needed...).
/// </summary>
public static class SyntheticPcs
{
    sealed class Fixed(string name, Func<CollectorOutput> run) : ICollector
    {
        public string Name => name;
        public CollectorOutput Run(CollectorContext context, CancellationToken ct) => run();
    }

    public sealed record Pc(string Name, IReadOnlyList<ICollector> Collectors, bool Offline = false);

    public static IEnumerable<Pc> All() => [Clean(), LooksInfected(), NoProtection(), FailingHardware(), PartialScan(), DeadDriveOffline()];

    // ---------- building blocks ----------
    static ICollector Out(string name, string kind, params IScanItem[] items) => new Fixed(name, () => new CollectorOutput(kind, items, []));

    static AvProduct Av(string key, string vendor, WscState? state, bool microsoft = false, string? accountUrl = null, string? status = null) =>
        new(key, vendor, vendor, state is null ? [] : ["antivirus"], true, ["test"], state, state is null ? null : true, microsoft, null,
            status ?? (state == WscState.On ? "on" : state?.ToString().ToLowerInvariant()), null, null, accountUrl, null, null, null, null);

    static PostureCheck Good(string id, string title, string finding) => new(id, title, PostureStatus.Good, PostureSeverity.Info, finding, "", $"{id}=ok");
    static PostureCheck Attention(string id, string title, PostureSeverity sev, string finding, string advice) => new(id, title, PostureStatus.Attention, sev, finding, advice, $"{id}=attention");
    static PostureCheck Risk(string id, string title, PostureSeverity sev, string finding, string advice) => new(id, title, PostureStatus.Risk, sev, finding, advice, $"{id}=risk");

    static PersistenceItem Startup(string name, Severity sev, string command, string? signer = null, SignatureStatus sig = SignatureStatus.Valid,
        string reason = "Signed by a known publisher.", bool disabled = false, string location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") =>
        new(location, name, command, null, null, signer, sig, sev, "RULE", reason, disabled, null);

    static InstalledApp App(string name, string version, string? publisher, string? winget = null, AppKind kind = AppKind.Win32) =>
        InstalledApp.Create(name, version, publisher, "x64", "Machine", kind, "test:" + name + version) with { WingetId = winget };

    static readonly PostureCheck[] AllGood =
    [
        Good("firewall", "Firewall", "The firewall is on for every type of network."),
        Good("uac", "User Account Control", "User Account Control is on."),
        Good("windows-update", "Windows updates", "Windows installed updates yesterday."),
    ];

    static PcProfile HealthyProfile(string name) => new()
    {
        ComputerName = name, ProductName = "Windows 11 Home", DisplayVersion = "25H2", Build = 26200, Ubr = 100, EditionId = "Core",
        Architecture = "x64", RamBytes = 16L << 30, LogicalProcessors = 8, SecureBoot = true, TpmPresent = true, TpmVersion = "2.0", Activated = true,
        PhysicalDisks = [new("0", "Samsung SSD 990", "SSD", "NVMe", 1_000_000_000_000, "Healthy", 3, 41, 1200)],
        LogicalDisks = [new("C:", 1_000_000_000_000, 400_000_000_000, "NTFS")],
        Crashes = new CrashSummary([], 0, 0, null, "test"),
    };

    // ---------- the PCs ----------
    public static Pc Clean() => new("clean",
    [
        Out("PC profile and health", "profile", HealthyProfile("FAMILY-PC")),
        Out("Antivirus", "av", Av("defender", "Microsoft Defender", WscState.On, microsoft: true)),
        Out("Security settings", "posture", AllGood),
        Out("Programs that start automatically", "persistence",
            Startup("SecurityHealth", Severity.Hidden, @"C:\Windows\System32\SecurityHealthSystray.exe", "Microsoft Windows"),
            Startup("OneDrive", Severity.Info, @"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background", "Microsoft Corporation")),
        Out("Installed apps", "apps", App("7-Zip", "26.06", "Igor Pavlov", "7zip.7zip"), App("Microsoft Photos", "2026.1", "Microsoft Corporation", kind: AppKind.Store),
            App("Family Recipes", "1.0", "Small Shop")),
    ]);

    public static Pc LooksInfected() => new("looks-infected",
    [
        Out("PC profile and health", "profile", HealthyProfile("OLD-LAPTOP")),
        Out("Antivirus", "av", Av("defender", "Microsoft Defender", WscState.On, microsoft: true)),
        Out("Security settings", "posture", AllGood),
        Out("Programs that start automatically", "persistence",
            Startup("updater", Severity.High, $@"C:\Users\bob\AppData\Roaming\upd\updater.exe --password={ReportInvariants.Canary}", null, SignatureStatus.Unsigned,
                "Runs from a user folder and is not signed.", location: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
            Startup("SyncTask", Severity.High, @"C:\ProgramData\g.exe -q", null, SignatureStatus.Unsigned,
                "This scheduled task is hidden from Task Scheduler (its security information is missing).", location: @"Task Scheduler\Microsoft"),
            Startup("OldToolbar", Severity.High, @"C:\Users\bob\AppData\Local\tb\tb.exe", null, SignatureStatus.Unsigned, "Not signed.", disabled: true),
            Startup("Sense", Severity.Medium, @"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe", "Microsoft Windows Publisher",
                reason: "The service's program path has spaces but no quotes."),
            Startup("<script>alert(1)</script>", Severity.Medium, "x.exe", "Contoso", reason: "Name from the scanned PC must be escaped.")),
        Out("Installed apps", "apps", App("Stack", "1.0.9", "Contoso"), App("Stack", "1.0.10", "Contoso"), App("Stack", "1.0.2", "Contoso")),
    ]);

    public static Pc NoProtection() => new("no-protection",
    [
        Out("PC profile and health", "profile", HealthyProfile("KIDS-PC")),
        Out("Antivirus", "av", Av("norton", "Norton", WscState.Expired, accountUrl: "https://my.norton.com", status: "license expired")),
        Out("Security settings", "posture",
            Risk("firewall", "Firewall", PostureSeverity.High, "The firewall is off for public networks.", "Turn the firewall on in Windows Security."),
            Attention("remote-desktop", "Remote Desktop", PostureSeverity.Low, "Remote Desktop is on.", "Turn it off if you do not use it."),
            Attention("smart-app-control", "Smart App Control", PostureSeverity.Info, "Smart App Control is off.", "No action needed; this is the norm on most PCs."),
            new PostureCheck("memory-integrity", "Memory integrity", PostureStatus.Unknown, PostureSeverity.Info, "We cannot tell whether it is on.", "", "")),
        Out("Programs that start automatically", "persistence"),
        Out("Installed apps", "apps", App("Norton 360", "22.1", "Gen Digital Inc.")),
    ]);

    public static Pc FailingHardware() => new("failing-hardware",
    [
        Out("PC profile and health", "profile", HealthyProfile("DESK-PC") with
        {
            PhysicalDisks = [new("0", "WD Blue", "HDD", "SATA", 1_000_000_000_000, "Warning", null, 61, 40000), new("1", "Kingston SSD", "SSD", "SATA", 240_000_000_000, "Healthy", 95, 38, 30000)],
            LogicalDisks = [new("C:", 240_000_000_000, 12_000_000_000, "NTFS"), new("D:", 1_000_000_000_000, 500_000_000_000, "NTFS")],
            Batteries = [new BatteryInfo("Main", "LG", "LION", 50000, 20000, 900, 40)],
            Crashes = new CrashSummary([new(DateTimeOffset.UnixEpoch, "0x1A"), new(DateTimeOffset.UnixEpoch, "0x50"), new(DateTimeOffset.UnixEpoch, "0x1A"), new(DateTimeOffset.UnixEpoch, "0xEF")], 2, 4, null, "test"),
            ProblemDevices = [new("Fingerprint Reader", 28), new("Old Webcam", 22), new("Bluetooth Mouse", 45), new("(unnamed device)", 10)],
            SecureBoot = false, TpmVersion = "1.2", Activated = false,
        }),
        Out("Antivirus", "av", Av("defender", "Microsoft Defender", WscState.On, microsoft: true)),
        Out("Security settings", "posture", AllGood),
    ]);

    public static Pc PartialScan() => new("partial-scan",
    [
        Out("PC profile and health", "profile", HealthyProfile("WORK-PC")),
        new Fixed("Antivirus", () => throw new IOException("Security Center did not answer")),
        new Fixed("Security settings", () => new CollectorOutput("posture", AllGood, ["2 checks could not be read."], CollectorStatus.Partial)),
    ]);

    /// <summary>A dead PC's drive: no WMI data, antivirus found only by its files (state unknown).</summary>
    public static Pc DeadDriveOffline() => new("dead-drive-offline",
    [
        Out("PC profile and health", "profile", new PcProfile { ComputerName = "OLD-PC", ProductName = "Windows 10 Pro", DisplayVersion = "22H2", Build = 19045, Ubr = 5000, EditionId = "Professional", Architecture = "x64" }),
        Out("Antivirus", "av", Av("avast", "Avast", null, accountUrl: "https://id.avast.com")),
        Out("Security settings", "posture", Good("firewall", "Firewall", "The firewall was on for every type of network.")),
        Out("Programs that start automatically", "persistence"),
        Out("Installed apps", "apps", App("Google Chrome", "120.0", "Google LLC", "Google.Chrome"), App("Avast Free Antivirus", "23.1", "Avast Software")),
    ], Offline: true);
}
