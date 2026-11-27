using PCPorter.Collectors.Offline;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Offline;

public class OfflineVolumeFinderTests
{
    static Dictionary<string, object?> Row(string? letter, uint protection, uint conversion, string id) => new()
    {
        ["DeviceID"] = id, ["DriveLetter"] = letter, ["ProtectionStatus"] = protection, ["ConversionStatus"] = conversion,
    };

    static string Hive(string root) => Path.Combine(root, "Windows", "System32", "config", "SOFTWARE");

    [Fact]
    public void Skips_running_windows_and_drives_without_software_hive_and_lists_locked_volumes()
    {
        var wmi = new FakeWmiClient().Add(OfflineVolumeFinder.BitLockerNamespace, "Win32_EncryptableVolume",
            Row("C:", 1, 1, @"\\?\Volume{c}\"),          // running Windows, unlocked
            Row("D:", 0, 0, @"\\?\Volume{d}\"),          // plain drive with Windows
            Row("F:", 2, 1, @"\\?\Volume{f}\"),          // locked
            Row(null, 2, 1, @"\\?\Volume{nolabel}\"),    // locked, no drive letter
            Row("C:", 2, 1, @"\\?\Volume{c2}\"));        // never offer the running volume
        var withHive = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Hive(@"C:\"), Hive(@"D:\") };
        var finder = new OfflineVolumeFinder(wmi, () => ["C:\\", "d:", "E:\\"], withHive.Contains, @"C:\",
            _ => ("Windows 11 Pro", "26100"));

        var scan = finder.Find();

        Assert.DoesNotContain(scan.Volumes, v => v.Root == @"C:\");
        Assert.DoesNotContain(scan.Volumes, v => v.Root == @"E:\");
        var d = Assert.Single(scan.Volumes, v => v.Root == @"D:\");
        Assert.Equal(OfflineVolumeState.WindowsFound, d.State);
        Assert.Equal("Windows 11 Pro", d.OsName);
        Assert.Equal("26100", d.Build);
        var f = Assert.Single(scan.Volumes, v => v.Root == @"F:\");
        Assert.Equal(OfflineVolumeState.Locked, f.State);
        Assert.Equal("locked - needs recovery key", f.Description);
        Assert.Equal(@"\\?\Volume{f}\", f.DeviceId);
        Assert.Single(scan.Volumes, v => v.Root is null && v.DeviceId == @"\\?\Volume{nolabel}\");
        Assert.Equal(3, scan.Volumes.Count);
    }

    [Fact]
    public void Access_denied_on_bitlocker_is_a_note_not_a_failure()
    {
        var wmi = new FakeWmiClient().Fail(OfflineVolumeFinder.BitLockerNamespace, "Win32_EncryptableVolume", WmiOutcome.AccessDenied);
        var scan = new OfflineVolumeFinder(wmi, () => [], _ => false, @"C:\").Find();
        Assert.Empty(scan.Volumes);
        Assert.Contains(scan.Notes, n => n.Contains("administrator", StringComparison.Ordinal));
    }

    [Fact]
    public void Reads_os_name_and_build_from_a_real_offline_hive()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-finder").FullName + "\\";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Hive(root))!);
            OffregHiveBuilder.Save(RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion", k => k
                .Str("SystemRoot", @"C:\Windows").Str("ProductName", "Windows 10 Enterprise").Str("CurrentBuild", "26200")), Hive(root));

            var scan = new OfflineVolumeFinder(new FakeWmiClient(), () => [root], runningWindowsDrive: @"C:\").Find();

            var v = Assert.Single(scan.Volumes);
            Assert.Equal("Windows 11 Enterprise", v.OsName);
            Assert.Equal("26200", v.Build);
            Assert.Equal("Windows 11 Enterprise (build 26200)", v.Description);
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData(2u, 1u, true)]
    [InlineData(1u, 1u, false)]
    [InlineData(0u, 0u, false)]
    public void Lock_state_from_protection_status(uint protection, uint conversion, bool locked) =>
        Assert.Equal(locked, OfflineVolumeFinder.IsLocked(new Dictionary<string, object?> { ["ProtectionStatus"] = protection, ["ConversionStatus"] = conversion }));

    [Theory]
    [InlineData("Windows 10 Pro", "19045", "Windows 10 Pro")]
    [InlineData("Windows 10 Pro", "22631", "Windows 11 Pro")]
    [InlineData("Windows 10 Enterprise", "26200", "Windows 11 Enterprise")]
    public void Os_name_uses_build_number(string product, string build, string expected) =>
        Assert.Equal(expected, OfflineVolumeFinder.OsName(product, build));

    [Theory]
    [InlineData("d", @"D:\")]
    [InlineData("D:", @"D:\")]
    [InlineData(@"e:\", @"E:\")]
    [InlineData("", null)]
    [InlineData("relative", null)]
    public void Normalizes_roots(string input, string? expected) => Assert.Equal(expected, OfflineVolumeFinder.NormalizeRoot(input));
}

public class BitLockerTests
{
    const string Valid = "000000-111111-222222-333333-444444-555555-666666-720885";

    [Theory]
    [InlineData(Valid)]
    [InlineData("  " + Valid + " ")]
    [InlineData("000000111111222222333333444444555555666666720885")]
    public void Accepts_valid_recovery_keys(string key) => Assert.True(BitLocker.ValidateRecoveryKey(key));

    [Theory]
    [InlineData("000000-111111-222222-333333-444444-555555-666666")]              // 7 groups
    [InlineData("000000-111111-222222-333333-444444-555555-666666-000000-000000")] // 9 groups
    [InlineData("000000-111111-222222-333333-444444-555555-666666-123456")]       // not divisible by 11
    [InlineData("000000-111111-222222-333333-444444-555555-666666-720896")]       // = 65536 * 11
    [InlineData("000000-111111-222222-333333-444444-555555-666666-777777")]       // divisible by 11 but too big
    [InlineData("000000-111111-222222-333333-444444-555555-66666a-000000")]       // not a digit
    [InlineData("000000 111111 222222 333333 444444 555555 666666 000000")]       // wrong separator
    [InlineData("00000-0111111-222222-333333-444444-555555-666666-000000")]       // misplaced dash
    [InlineData("")]
    public void Rejects_invalid_recovery_keys(string key) => Assert.False(BitLocker.ValidateRecoveryKey(key));

    [Fact]
    public void Unlock_with_a_malformed_key_never_reaches_wmi_and_wipes_the_key()
    {
        var key = "123456-111111-222222-333333-444444-555555-666666-000000".ToCharArray();
        var result = BitLocker.Unlock(@"\\?\Volume{00000000-0000-0000-0000-000000000000}\", key);
        Assert.Equal(UnlockOutcome.InvalidKeyFormat, result.Outcome);
        Assert.All(key, c => Assert.Equal('\0', c));
        Assert.DoesNotContain("123456", result.Message, StringComparison.Ordinal);
    }
}

public sealed class VolumeSafetyTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-safety").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    void Hiberfil(params byte[] header) => File.WriteAllBytes(Path.Combine(_root, "hiberfil.sys"), [.. header, .. new byte[64]]);

    [Fact]
    public void Hibernation_header_upper_case() { Hiberfil("HIBR"u8.ToArray()); Assert.True(VolumeSafety.IsHibernated(_root)); }

    [Fact]
    public void Hibernation_header_lower_case() { Hiberfil("hibr"u8.ToArray()); Assert.True(VolumeSafety.IsHibernated(_root)); }

    [Fact]
    public void Other_header_is_not_hibernated() { Hiberfil("wake"u8.ToArray()); Assert.False(VolumeSafety.IsHibernated(_root)); }

    [Fact]
    public void Zeroed_or_short_hiberfil_is_not_hibernated()
    {
        File.WriteAllBytes(Path.Combine(_root, "hiberfil.sys"), [0x48, 0x49]);
        Assert.False(VolumeSafety.IsHibernated(_root));
    }

    [Fact]
    public void Missing_hiberfil_is_not_hibernated() => Assert.False(VolumeSafety.IsHibernated(_root));

    [Fact]
    public void Report_warns_when_hibernated_or_dirty()
    {
        Assert.Equal(VolumeSafetyReport.UncleanWarning, new VolumeSafetyReport(true, null, null).Warning);
        Assert.Equal(VolumeSafetyReport.UncleanWarning, new VolumeSafetyReport(false, true, 5).Warning);
        Assert.Null(new VolumeSafetyReport(false, false, 5).Warning);
        Assert.Null(new VolumeSafetyReport(null, null, null).Warning);
    }

    [Fact]
    public void Usn_change_is_a_warning()
    {
        Assert.NotNull(VolumeSafety.UsnChangeWarning(100, 200));
        Assert.Null(VolumeSafety.UsnChangeWarning(100, 100));
        Assert.Null(VolumeSafety.UsnChangeWarning(null, 200));
    }

    [Fact]
    public void Device_checks_on_a_folder_return_null()
    {
        Assert.Null(VolumeSafety.IsDirty(_root));
        Assert.Null(VolumeSafety.NextUsn(_root));
    }

    [Fact]
    public void Device_checks_on_the_system_drive_are_best_effort()
    {
        var report = VolumeSafety.Check(Path.GetPathRoot(Environment.SystemDirectory)!);   // null when not elevated
        if (AdminFactAttribute.IsAdmin) Assert.NotNull(report.Dirty);
    }
}

public class ReadOnlyAttachGuideTests
{
    [Fact]
    public void Before_attach_keeps_new_disks_offline() => Assert.Equal("san policy=OfflineAll\r\n", ReadOnlyAttachGuide.BeforeAttachScript());

    [Fact]
    public void After_attach_marks_the_disk_read_only_before_online() =>
        Assert.Equal("select disk 2\r\nattributes disk set readonly\r\nonline disk\r\n", ReadOnlyAttachGuide.AfterAttachScript(2));

    [Fact]
    public void Negative_disk_number_is_refused() => Assert.Throws<ArgumentOutOfRangeException>(() => ReadOnlyAttachGuide.AfterAttachScript(-1));

    [Theory]
    [InlineData("OnlineAll", "san policy=OnlineAll\r\n")]
    [InlineData("offlineshared", "san policy=OfflineShared\r\n")]
    public void Restore_policy(string previous, string expected) => Assert.Equal(expected, ReadOnlyAttachGuide.RestorePolicyScript(previous));

    [Fact]
    public void Restore_refuses_unknown_policies() => Assert.Throws<ArgumentException>(() => ReadOnlyAttachGuide.RestorePolicyScript("OnlineAll\r\nclean"));

    [Theory]
    [InlineData("\r\nSAN Policy  : Offline Shared\r\n", "OfflineShared")]
    [InlineData("SAN Policy  : Online All", "OnlineAll")]
    [InlineData("nothing here", null)]
    public void Parses_san_output(string output, string? expected) => Assert.Equal(expected, ReadOnlyAttachGuide.ParseSanPolicy(output));

    [Fact]
    public void Never_writes_persistent_attributes_to_the_old_disk()
    {
        var all = string.Join("\n", ReadOnlyAttachGuide.QuerySanPolicyScript(), ReadOnlyAttachGuide.BeforeAttachScript(),
            ReadOnlyAttachGuide.AfterAttachScript(0), ReadOnlyAttachGuide.RestorePolicyScript("OfflineShared"),
            string.Join("\n", ReadOnlyAttachGuide.Steps(1)), string.Join("\n", ReadOnlyAttachGuide.Steps()));
        Assert.DoesNotContain("attributes volume", all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("gpt attributes", all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("clean", all, StringComparison.OrdinalIgnoreCase);
    }
}
