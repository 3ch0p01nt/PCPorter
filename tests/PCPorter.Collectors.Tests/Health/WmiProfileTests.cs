using PCPorter.Collectors.Health;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;
using static PCPorter.Collectors.Tests.Health.TestContexts;

namespace PCPorter.Collectors.Tests.Health;

public class WmiProfileTests
{
    const string Cim = WmiProfile.Cimv2;
    const string Sto = WmiProfile.StorageNs;

    static PcProfile Apply(IWmiClient wmi, out List<string> warnings)
    {
        warnings = [];
        return WmiProfile.Apply(new PcProfile(), wmi, warnings);
    }

    [Fact]
    public void Reads_hardware_and_joins_reliability_counters_on_device_id()
    {
        var wmi = new FakeWmiClient()
            .Add(Cim, "Win32_Processor", Row(("Name", "Test CPU"), ("NumberOfCores", 8u), ("NumberOfLogicalProcessors", 16u)))
            .Add(Cim, "Win32_ComputerSystem", Row(("TotalPhysicalMemory", 34359738368UL), ("Manufacturer", "Contoso"), ("Model", "Laptop 1"), ("PartOfDomain", false)))
            .Add(Cim, "Win32_VideoController", Row(("Name", "GPU"), ("DriverVersion", "31.0")))
            .Add(Cim, "Win32_LogicalDisk", Row(("DeviceID", "C:"), ("Size", 1000UL), ("FreeSpace", 400UL), ("FileSystem", "NTFS")))
            .Add(Sto, "MSFT_PhysicalDisk",
                Row(("DeviceId", "0"), ("FriendlyName", "NVMe Disk"), ("MediaType", (ushort)4), ("BusType", (ushort)17), ("Size", 512UL), ("HealthStatus", (ushort)0)),
                Row(("DeviceId", "1"), ("FriendlyName", "USB Disk"), ("MediaType", (ushort)3), ("BusType", (ushort)7), ("Size", 1024UL)))
            .Add(Sto, "MSFT_StorageReliabilityCounter", Row(("DeviceId", "0"), ("Wear", (byte)12), ("Temperature", (byte)40), ("PowerOnHours", 1234UL)));
        var p = Apply(wmi, out _);
        Assert.Equal("Test CPU", p.Processor);
        Assert.Equal(8, p.Cores);
        Assert.Equal(16, p.LogicalProcessors);
        Assert.Equal(34359738368L, p.RamBytes);
        Assert.False(p.DomainJoined);
        Assert.Equal("C:", p.LogicalDisks!.Single().Drive);
        var nvme = p.PhysicalDisks!.Single(d => d.DeviceId == "0");
        Assert.Equal(("SSD", "NVMe", 12, 40, 1234L), (nvme.MediaType, nvme.BusType, nvme.WearPercent!.Value, nvme.TemperatureC!.Value, nvme.PowerOnHours!.Value));
        var usb = p.PhysicalDisks!.Single(d => d.DeviceId == "1");
        Assert.Equal(("HDD", "USB"), (usb.MediaType, usb.BusType));
        Assert.Null(usb.WearPercent);   // no counter => null, never 0
        Assert.Null(usb.PowerOnHours);
    }

    [Theory]
    [InlineData("2.0, 0, 1.59", "2.0")]
    [InlineData("1.2, 2, 3", "1.2")]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Tpm_version_is_first_token(string? spec, string? expected) => Assert.Equal(expected, WmiProfile.TpmVersion(spec));

    [Fact]
    public void Tpm_from_wmi()
    {
        var p = Apply(new FakeWmiClient().Add(WmiProfile.TpmNs, "Win32_Tpm", Row(("SpecVersion", "2.0, 0, 1.59"))), out _);
        Assert.True(p.TpmPresent);
        Assert.Equal("2.0", p.TpmVersion);
    }

    [Fact]
    public void Access_denied_is_unknown_not_absent()
    {
        var wmi = new FakeWmiClient()
            .Fail(WmiProfile.TpmNs, "Win32_Tpm", WmiOutcome.AccessDenied)
            .Fail(WmiProfile.BitLockerNs, "Win32_EncryptableVolume", WmiOutcome.AccessDenied)
            .Add(Sto, "MSFT_PhysicalDisk", Row(("DeviceId", "0"), ("MediaType", (ushort)4)))
            .Fail(Sto, "MSFT_StorageReliabilityCounter", WmiOutcome.AccessDenied);
        var p = Apply(wmi, out _);
        Assert.Null(p.TpmPresent);
        Assert.Null(p.TpmVersion);
        Assert.Null(p.BitLocker);
        Assert.Equal(PcProfile.NotElevated, p.Unknown["tpm"]);
        Assert.Equal(PcProfile.NotElevated, p.Unknown["bitlocker"]);
        Assert.Equal(PcProfile.NotElevated, p.Unknown["diskWear"]);
        Assert.Null(p.PhysicalDisks!.Single().WearPercent);
    }

    [Fact]
    public void Invalid_namespace_and_timeouts_leave_nulls_and_warn()
    {
        var wmi = new FakeWmiClient()
            .Fail(Cim, "Win32_Processor", WmiOutcome.TimedOut)
            .Fail(Sto, "MSFT_PhysicalDisk", WmiOutcome.InvalidNamespace);
        var p = Apply(wmi, out var warnings);
        Assert.Null(p.Processor);
        Assert.Null(p.PhysicalDisks);
        Assert.Null(p.Activated);
        Assert.Contains(warnings, w => w.Contains("TimedOut", StringComparison.Ordinal));
        Assert.Contains(warnings, w => w.Contains("InvalidNamespace", StringComparison.Ordinal));
        Assert.Empty(p.Unknown);
    }

    [Fact]
    public void Activation_uses_the_exact_query_with_a_45_second_timeout()
    {
        var wmi = new RecordingWmiClient(new FakeWmiClient().Add(Cim, "SoftwareLicensingProduct",
            Row(("LicenseStatus", 1u), ("ProductKeyChannel", "OEM:DM"))));
        var p = WmiProfile.Apply(new PcProfile(), wmi, new List<string>());
        Assert.True(p.Activated);
        Assert.Equal("OEM:DM", p.ActivationChannel);
        var call = wmi.Calls.Single(c => c.Wql.Contains("SoftwareLicensingProduct"));
        Assert.Equal("SELECT LicenseStatus, ProductKeyChannel FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL", call.Wql);
        Assert.Equal(TimeSpan.FromSeconds(45), call.Timeout);
        Assert.DoesNotContain(wmi.Calls, c => c.Wql.Contains("GetKeyProtectorNumericalPassword", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Not_activated_when_no_licensed_row()
    {
        var p = Apply(new FakeWmiClient().Add(Cim, "SoftwareLicensingProduct", Row(("LicenseStatus", 5u), ("ProductKeyChannel", "Retail"))), out _);
        Assert.False(p.Activated);
    }

    [Fact]
    public void Bitlocker_devices_and_newest_stability_only()
    {
        var wmi = new FakeWmiClient()
            .Add(WmiProfile.BitLockerNs, "Win32_EncryptableVolume", Row(("DriveLetter", "C:"), ("ProtectionStatus", 1u)), Row(("DriveLetter", "D:"), ("ProtectionStatus", 0u)))
            .Add(Cim, "Win32_PnPEntity", Row(("Name", "Unknown device"), ("ConfigManagerErrorCode", 28u)))
            .Add(Cim, "Win32_ReliabilityStabilityMetrics",
                Row(("SystemStabilityIndex", 9.5), ("TimeGenerated", "20261120100000.000000-000")),
                Row(("SystemStabilityIndex", 6.25), ("TimeGenerated", "20261125100000.000000-000")),
                Row(("SystemStabilityIndex", 8.0), ("TimeGenerated", "20261101100000.000000-000")));
        var p = Apply(wmi, out _);
        Assert.Equal([new BitLockerVolume("C:", "on"), new BitLockerVolume("D:", "off")], p.BitLocker);
        Assert.Equal(new ProblemDevice("Unknown device", 28), p.ProblemDevices!.Single());
        Assert.Equal(6.25, p.StabilityIndex);
        Assert.Equal(new DateTimeOffset(2026, 11, 25, 10, 0, 0, TimeSpan.Zero), p.StabilityTime);
    }

    [Fact]
    public void Device_query_filters_on_error_code()
    {
        var wmi = new RecordingWmiClient(new FakeWmiClient());
        WmiProfile.Apply(new PcProfile(), wmi, new List<string>());
        Assert.Contains(wmi.Calls, c => c.Wql.Contains("Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0", StringComparison.Ordinal));
        Assert.All(wmi.Calls, c => Assert.StartsWith("SELECT ", c.Wql));
    }

    [Fact]
    public void Monitors_join_wmi_make_and_serial_by_device_path()
    {
        static ushort[] U(string s) => s.Select(c => (ushort)c).Concat(new ushort[] { 0, 0, 0 }).ToArray();
        var wmi = new FakeWmiClient().Add(WmiProfile.WmiNs, "WmiMonitorID",
            Row(("InstanceName", @"DISPLAY\DEL4321\5&abc&0&UID4352_0"), ("ManufacturerName", U("DEL")), ("SerialNumberID", U("SER123")), ("UserFriendlyName", U("DELL U2720Q"))));
        var native = new[]
        {
            new NativeMonitor("DELL U2720Q", 3840, 2160, 150, @"\\?\DISPLAY#DEL4321#5&abc&0&UID4352#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}"),
            new NativeMonitor(null, 1920, 1080, 100, null),
        };
        var list = WmiProfile.Monitors(native, wmi, new List<string>());
        Assert.Equal(new MonitorInfo("DELL U2720Q", 3840, 2160, 150, "DEL", "SER123"), list[0]);
        Assert.Equal(new MonitorInfo(null, 1920, 1080, 100, null, null), list[1]);
    }
}
