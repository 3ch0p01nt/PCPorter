using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;
using static PCPorter.Collectors.Tests.Apps.AppTest;

namespace PCPorter.Collectors.Tests.Apps;

public class RegistryAppTests : IDisposable
{
    readonly FakeDrive _drive = new();
    public void Dispose() => _drive.Dispose();

    List<InstalledApp> Apps(RegSpec software, RegSpec? bobHive = null, IReadOnlyList<UserProfile>? users = null)
    {
        var src = new FakeSystemSource(_drive.Root, software,
            userHives: bobHive is null ? null : new Dictionary<string, RegSpec> { [Bob.Sid] = bobHive },
            users: users ?? (bobHive is null ? [] : [Bob]));
        var (apps, output, warnings) = Run(src, _drive.Work);
        Assert.Equal("apps", output.Kind);
        Assert.Empty(warnings);
        return apps;
    }

    [Fact]
    public void Packed_guids_unpack()
    {
        Assert.Equal("{23170F69-40C1-2701-1604-000001000000}", AppInventoryCollector.UnpackGuid("96F071321C0410726140000010000000"));
        Assert.Null(AppInventoryCollector.UnpackGuid("not-a-packed-guid"));
        Assert.Null(AppInventoryCollector.UnpackGuid("96F071321C041072614000001000000Z"));
    }

    [Fact]
    public void Upgrade_codes_come_from_the_installer_keys()
    {
        var sw = RegSpec.Root()
            .Key(Uninstall + @"\{23170F69-40C1-2701-1604-000001000000}", k => k.Str("DisplayName", "7-Zip").Num("WindowsInstaller", 1))
            .Key(@"Classes\Installer\UpgradeCodes\44CEA411B251647559F22FC03EAC5BA4", k => k.Str("96F071321C0410726140000010000000", ""));
        var app = Assert.Single(Apps(sw));
        Assert.Equal("{114AEC44-152B-5746-952F-F20CE3CAB54A}", app.UpgradeCode);
    }

    [Fact]
    public void Side_by_side_versions_get_unique_stable_keys()
    {
        var sw = RegSpec.Root()
            .Key(Uninstall + @"\Photos", k => k.Str("DisplayName", "Family Photos").Str("DisplayVersion", "3.0").Str("Publisher", "Small Shop"))
            .Key(Uninstall + @"\Photos_2", k => k.Str("DisplayName", "Family Photos").Str("DisplayVersion", "2.0").Str("Publisher", "Small Shop"))
            .Key(Uninstall + @"\Other", k => k.Str("DisplayName", "Other"));
        var apps = Apps(sw);
        AppInventoryCollector.MakeKeysUnique(apps);

        Assert.Equal(3, apps.Select(a => a.ItemKey).Distinct(StringComparer.Ordinal).Count());
        Assert.EndsWith(@"|hklm\software\" + Uninstall.ToLowerInvariant() + @"\photos_2", apps.Single(a => a.Version == "2.0").ItemKey);
        var other = apps.Single(a => a.Name == "Other");
        Assert.Equal(InstalledApp.KeyFor("Other", null, other.Scope, other.Architecture), other.ItemKey);   // no clash: unchanged
    }

    [Fact]
    public void Rule1_reads_machine_and_user_uninstall_keys_in_both_views()
    {
        var sw = RegSpec.Root()
            .Key(Uninstall + @"\App64", k => k.Str("DisplayName", "Sixty Four"))
            .Key(Uninstall32 + @"\App32", k => k.Str("DisplayName", "Thirty Two"));
        var user = RegSpec.Root()
            .Key(UserUninstall + @"\UserApp", k => k.Str("DisplayName", "User App"))
            .Key(@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\UserApp32", k => k.Str("DisplayName", "User App 32"));
        var apps = Apps(sw, user);

        Assert.Equal(4, apps.Count);
        Assert.Equal(("x64", "Machine"), apps.Where(a => a.Name == "Sixty Four").Select(a => (a.Architecture, a.Scope)).Single());
        Assert.Equal(("x86", "Machine"), apps.Where(a => a.Name == "Thirty Two").Select(a => (a.Architecture, a.Scope)).Single());
        Assert.Equal(("x64", "User:bob"), apps.Where(a => a.Name == "User App").Select(a => (a.Architecture, a.Scope)).Single());
        Assert.Equal(("x86", "User:bob"), apps.Where(a => a.Name == "User App 32").Select(a => (a.Architecture, a.Scope)).Single());
        Assert.Equal(@"HKLM\SOFTWARE\" + Uninstall + @"\App64", apps.Single(a => a.Name == "Sixty Four").SourceKey);
        Assert.All(apps, a => Assert.Equal(AppKind.Win32, a.Kind));
        Assert.All(apps, a => Assert.True(a.ReinstallCandidate));
    }

    [Fact]
    public void Compatibility_fix_databases_are_not_apps_to_reinstall()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\{22221111-1111-1111-1111-111111111111}.sdb", k => k.Str("DisplayName", "Microsoft Windows Application Compatibility Fix Database"))
            .Key(Uninstall32 + @"\Real", k => k.Str("DisplayName", "Real")));
        var sdb = apps.Single(a => a.Name.Contains("Compatibility"));
        Assert.True(sdb.Hidden);
        Assert.False(sdb.ReinstallCandidate);
        Assert.True(apps.Single(a => a.Name == "Real").ReinstallCandidate);
    }

    [Fact]
    public void Shortcuts_into_a_users_own_program_files_are_not_portable_apps()
    {
        var bob = Bob with { OriginalPath = @"C:\Users\bob" };
        var src = new FakeSystemSource(_drive.Root, RegSpec.Root(), users: [bob]);
        var known = PortableAppFinder.KnownFolders(src, []);
        var found = PortableAppFinder.Classify(
        [
            new(@"x\Python 3.12 (64-bit).lnk", "User:bob", @"C:\Users\bob\AppData\Local\Programs\Python\Python312\python.exe"),
            new(@"x\Tool.lnk", "User:bob", @"D:\Tools\Tool\tool.exe"),
        ], known);
        Assert.Equal("Tool", Assert.Single(found).Name);
    }

    [Fact]
    public void Rule1_32bit_windows_without_wow6432node_is_x86()
    {
        var apps = Apps(RegSpec.Root().Key(Uninstall + @"\A", k => k.Str("DisplayName", "A")));
        Assert.Equal("x86", Assert.Single(apps).Architecture);
    }

    [Fact]
    public void Rule2_entries_without_display_name_are_skipped()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\NoName", k => k.Str("UninstallString", "x.exe"))
            .Key(Uninstall + @"\Blank", k => k.Str("DisplayName", "   "))
            .Key(Uninstall32 + @"\Real", k => k.Str("DisplayName", "Real")));
        Assert.Equal("Real", Assert.Single(apps).Name);
    }

    [Fact]
    public void Rule2_system_components_and_bundle_children_are_kept_hidden_and_not_reinstalled()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\Dword", k => k.Str("DisplayName", "Dword").Num("SystemComponent", 1))
            .Key(Uninstall + @"\Text", k => k.Str("DisplayName", "Text").Str("SystemComponent", "1"))
            .Key(Uninstall + @"\Child", k => k.Str("DisplayName", "Child").Str("ParentKeyName", "Bundle"))
            .Key(Uninstall + @"\Zero", k => k.Str("DisplayName", "Zero").Num("SystemComponent", 0))
            .Key(Uninstall32));
        Assert.Equal(4, apps.Count);
        foreach (var n in new[] { "Dword", "Text", "Child" })
        {
            var a = apps.Single(x => x.Name == n);
            Assert.True(a.Hidden, n);
            Assert.False(a.ReinstallCandidate, n);
        }
        Assert.False(apps.Single(x => x.Name == "Zero").Hidden);
        Assert.True(apps.Single(x => x.Name == "Zero").ReinstallCandidate);
    }

    [Fact]
    public void Rule2_updates_hotfixes_and_security_updates_are_skipped()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\KB1", k => k.Str("DisplayName", "Update for X").Str("ReleaseType", "Update"))
            .Key(Uninstall + @"\KB2", k => k.Str("DisplayName", "Hotfix for X").Str("ReleaseType", "Hotfix"))
            .Key(Uninstall + @"\KB3", k => k.Str("DisplayName", "Security Update for X").Str("ReleaseType", "Security Update"))
            .Key(Uninstall + @"\SP", k => k.Str("DisplayName", "X Service Pack").Str("ReleaseType", "Service Pack"))
            .Key(Uninstall32));
        Assert.Equal("X Service Pack", Assert.Single(apps).Name);
    }

    [Fact]
    public void Rule3_dedup_is_on_key_name_scope_and_arch_not_name_and_version()
    {
        var sw = RegSpec.Root()
            .Key(Uninstall + @"\Python3.12", k => k.Str("DisplayName", "Python 3.12.1 (64-bit)").Str("DisplayVersion", "3.12.1"))
            .Key(Uninstall32 + @"\Python3.12", k => k.Str("DisplayName", "Python 3.12.1 (64-bit)").Str("DisplayVersion", "3.12.1"))
            .Key(Uninstall + @"\Other", k => k.Str("DisplayName", "Python 3.12.1 (64-bit)").Str("DisplayVersion", "3.12.1"));
        var user = RegSpec.Root().Key(UserUninstall + @"\Python3.12", k => k.Str("DisplayName", "Python 3.12.1 (64-bit)"));
        // bob listed twice (same hive seen twice) => his entry is kept once
        var apps = Apps(sw, user, [Bob, Bob]);
        Assert.Equal(4, apps.Count);
        Assert.Equal(2, apps.Count(a => a.SourceKey.EndsWith(@"\Python3.12") && a.Scope == "Machine"));
        Assert.Single(apps, a => a.Scope == "User:bob");
    }

    [Fact]
    public void Rule4_install_date_yyyymmdd_else_key_last_write_inferred()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\Good", k => k.Str("DisplayName", "Good").Str("InstallDate", "20240315"))
            .Key(Uninstall + @"\Bad", k => k.Str("DisplayName", "Bad").Str("InstallDate", "3/15/2024"))
            .Key(Uninstall + @"\None", k => k.Str("DisplayName", "None"))
            .Key(Uninstall32));
        var good = apps.Single(a => a.Name == "Good");
        Assert.Equal(new DateOnly(2024, 3, 15), good.InstallDate);
        Assert.False(good.InstallDateInferred);
        foreach (var n in new[] { "Bad", "None" })
        {
            var a = apps.Single(x => x.Name == n);
            Assert.Equal(new DateOnly(2026, 1, 1), a.InstallDate);       // FakeRegKey LastWrite
            Assert.True(a.InstallDateInferred);
        }
    }

    [Fact]
    public void Rule4_no_last_write_means_no_date() =>
        Assert.Equal((null, false), AppInventoryCollector.InstallDateOf("garbage", null));

    [Fact]
    public void Rule5_runtimes_and_drivers_are_classified_and_not_reinstalled()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\Vc", k => k.Str("DisplayName", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135"))
            .Key(Uninstall + @"\Nv", k => k.Str("DisplayName", "NVIDIA Graphics Driver 551.23"))
            .Key(Uninstall + @"\Steam App 440", k => k.Str("DisplayName", "Steam App 440"))
            .Key(Uninstall + @"\App", k => k.Str("DisplayName", "Notepad++ (64-bit x64)"))
            .Key(Uninstall32));
        Assert.Equal(AppKind.Runtime, apps.Single(a => a.Name.StartsWith("Microsoft Visual")).Kind);
        Assert.Equal(AppKind.Driver, apps.Single(a => a.Name.StartsWith("NVIDIA")).Kind);
        Assert.Equal(AppKind.Game, apps.Single(a => a.Name == "Steam App 440").Kind);
        Assert.Equal(AppKind.Win32, apps.Single(a => a.Name.StartsWith("Notepad")).Kind);
        Assert.False(apps.Single(a => a.Kind == AppKind.Runtime).ReinstallCandidate);
        Assert.False(apps.Single(a => a.Kind == AppKind.Driver).ReinstallCandidate);
        Assert.True(apps.Single(a => a.Kind == AppKind.Game).ReinstallCandidate);
    }

    [Fact]
    public void Rule6_product_code_from_guid_key_names_and_windows_installer_flag()
    {
        const string guid = "{12345678-ABCD-ABCD-ABCD-1234567890AB}";
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + "\\" + guid, k => k.Str("DisplayName", "Msi App").Num("WindowsInstaller", 1)
                .Str("Publisher", "Contoso").Str("DisplayVersion", "1.0").Str("InstallLocation", "\"C:\\Program Files\\Msi App\\\"")
                .Str("UninstallString", "MsiExec.exe /X" + guid).Str("QuietUninstallString", "q").Str("HelpLink", "h").Str("URLInfoAbout", "u"))
            .Key(Uninstall + @"\NotAGuid", k => k.Str("DisplayName", "Exe App"))
            .Key(Uninstall32));
        var msi = apps.Single(a => a.Name == "Msi App");
        Assert.Equal(guid, msi.ProductCode);
        Assert.True(msi.WindowsInstaller);
        Assert.Equal(("Contoso", "1.0", @"C:\Program Files\Msi App\", "q", "h", "u"),
            (msi.Publisher, msi.Version, msi.InstallLocation, msi.QuietUninstallString, msi.HelpLink, msi.UrlInfoAbout));
        var exe = apps.Single(a => a.Name == "Exe App");
        Assert.Null(exe.ProductCode);
        Assert.False(exe.WindowsInstaller);
    }

    [Fact]
    public void Item_key_is_normalized_name_publisher_scope_arch()
    {
        var apps = Apps(RegSpec.Root()
            .Key(Uninstall + @"\7-Zip", k => k.Str("DisplayName", "7-Zip 23.01 (x64)").Str("Publisher", "Igor Pavlov"))
            .Key(Uninstall32));
        Assert.Equal("7-zip|Igor Pavlov|Machine|x64", Assert.Single(apps).ItemKey);
    }

    [Fact]
    public void A_bad_entry_becomes_a_warning_not_an_exception()
    {
        var src = new FakeSystemSource(_drive.Root, RegSpec.Root().Key(Uninstall32));
        var broken = new ThrowingSource(src);
        var (apps, output, warnings) = Run(broken, _drive.Work);
        Assert.Empty(apps);
        Assert.NotEmpty(warnings);
        Assert.Equal(CollectorStatus.Ok, output.Status);
    }

    [Fact]
    public void Unreadable_user_hive_is_a_note()
    {
        var src = new FakeSystemSource(_drive.Root, RegSpec.Root(), users: [Bob]);
        var (_, output, _) = Run(src, _drive.Work);
        Assert.Contains(output.Notes, n => n.Contains("bob"));
    }

    /// <summary>SOFTWARE whose Uninstall subkeys throw when read (simulates a corrupt key).</summary>
    sealed class ThrowingSource(ISystemSource inner) : ISystemSource
    {
        public bool IsLive => inner.IsLive;
        public string ReadRoot => inner.ReadRoot;
        public string OriginalSystemDrive => inner.OriginalSystemDrive;
        public IReadOnlyList<UserProfile> Users => inner.Users;
        public IReadOnlyList<string> Notes => inner.Notes;
        public string? MapPath(string p) => inner.MapPath(p);
        public string? CurrentControlSet() => inner.CurrentControlSet();
        public IRegKey? OpenHive(Hive hive, UserProfile? user = null) => hive == Hive.Software ? new Root() : null;
        public void Dispose() { }

        sealed class Root : IRegKey
        {
            public string Name => "SOFTWARE";
            public DateTimeOffset? LastWrite => null;
            public IEnumerable<IRegKey> SubKeys => [];
            public IEnumerable<string> ValueNames => [];
            public IRegKey? Open(string relativePath) => relativePath.EndsWith("Uninstall") ? new Bad() : null;
            public (RegType Type, byte[] Raw)? GetRaw(string valueName) => null;
        }

        sealed class Bad : IRegKey
        {
            public string Name => "Uninstall";
            public DateTimeOffset? LastWrite => null;
            public IEnumerable<IRegKey> SubKeys => [new Boom()];
            public IEnumerable<string> ValueNames => [];
            public IRegKey? Open(string relativePath) => null;
            public (RegType Type, byte[] Raw)? GetRaw(string valueName) => null;
        }

        sealed class Boom : IRegKey
        {
            public string Name => "Boom";
            public DateTimeOffset? LastWrite => null;
            public IEnumerable<IRegKey> SubKeys => [];
            public IEnumerable<string> ValueNames => [];
            public IRegKey? Open(string relativePath) => null;
            public (RegType Type, byte[] Raw)? GetRaw(string valueName) => throw new InvalidDataException("corrupt cell");
        }
    }
}

/// <summary>Per-user installs read from a REAL hive file (offreg-built NTUSER.DAT) through OfflineSource.</summary>
public class RegistryAppOffregTests : IDisposable
{
    readonly FakeDrive _drive = new();
    public void Dispose() => _drive.Dispose();

    [Fact]
    public void Per_user_installs_from_a_real_ntuser_hive()
    {
        var config = Directory.CreateDirectory(_drive.At(@"C:\Windows\System32\config")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Str("SystemRoot", @"C:\Windows"))
            .Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList\" + AppTest.Bob.Sid, k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob"))
            .Key(AppTest.Uninstall + @"\MachineApp", k => k.Str("DisplayName", "Machine App").Str("InstallDate", "20250101"))
            .Key(AppTest.Uninstall32 + @"\{11111111-2222-3333-4444-555555555555}", k => k.Str("DisplayName", "Old App").Str("SystemComponent", "1")),
            Path.Combine(config, "SOFTWARE"));
        OffregHiveBuilder.Save(RegSpec.Root(), Path.Combine(config, "SYSTEM"));
        var bob = Directory.CreateDirectory(_drive.At(@"C:\Users\bob")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(AppTest.UserUninstall + @"\Code", k => k.Str("DisplayName", "Microsoft Visual Studio Code (User)").Str("DisplayVersion", "1.95.0")
                .Str("InstallLocation", @"C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\").Str("InstallDate", "bogus")),
            Path.Combine(bob, "NTUSER.DAT"));

        using var src = new OfflineSource(_drive.Root, runningWindowsDrive: @"Z:\");
        var (apps, output, warnings) = AppTest.Run(src, _drive.Work);

        Assert.Empty(warnings);
        Assert.Equal(3, apps.Count);
        var code = apps.Single(a => a.Scope == "User:bob");
        Assert.Equal(("Microsoft Visual Studio Code (User)", "1.95.0", "x64"), (code.Name, code.Version, code.Architecture));
        Assert.True(code.InstallDateInferred);                               // real hive LastWrite used
        Assert.NotNull(code.InstallDate);
        var old = apps.Single(a => a.Name == "Old App");
        Assert.True(old.Hidden);
        Assert.Equal("{11111111-2222-3333-4444-555555555555}", old.ProductCode);
        Assert.Equal(new DateOnly(2025, 1, 1), apps.Single(a => a.Name == "Machine App").InstallDate);
        Assert.Equal(CollectorStatus.Ok, output.Status);
    }
}
