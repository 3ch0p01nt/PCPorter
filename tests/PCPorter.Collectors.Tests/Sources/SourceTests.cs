using PCPorter.Collectors.Sources;
using PCPorter.Core;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Sources;

public class SourcePathsTests
{
    [Theory]
    [InlineData(@"%SystemDrive%\Users\bob", @"D:\Users\bob")]
    [InlineData(@"c:\windows\system32\x.exe", @"D:\windows\system32\x.exe")]
    [InlineData(@"""C:\Program Files\App\app.exe""", @"D:\Program Files\App\app.exe")]
    [InlineData(@"%ProgramFiles%\App\a.exe", @"D:\Program Files\App\a.exe")]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", @"D:\Windows\System32\drivers\x.sys")]
    [InlineData(@"\??\C:\Windows\x.sys", @"D:\Windows\x.sys")]
    [InlineData(@"system32\drivers\x.sys", @"D:\Windows\system32\drivers\x.sys")]
    public void Maps_scanned_pc_paths_onto_the_drive(string input, string expected) =>
        Assert.Equal(expected, SourcePaths.Map(input, "C:", @"D:\"));

    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" /background", @"D:\Program Files\App\app.exe")]
    [InlineData(@"C:/Windows/x.exe", @"D:\Windows\x.exe")]
    [InlineData(@"\\.\C:\Windows\x.sys", @"D:\Windows\x.sys")]
    [InlineData(@"C:\Windows\System32\..\explorer.exe", @"D:\Windows\explorer.exe")]
    public void Handles_arguments_slashes_and_dot_segments(string input, string expected) =>
        Assert.Equal(expected, SourcePaths.Map(input, "C:", @"D:\"));

    [Theory]
    [InlineData(@"E:\Data\x.jpg")]
    [InlineData(@"\\server\share\x")]
    [InlineData("")]
    [InlineData("notepad.exe")]
    [InlineData(@"C:\..\..\x")]                       // climbs above the drive
    [InlineData(@"C:\a b\x.exe"" /y")]               // stray quote: not a single path
    public void Other_volumes_or_relative_paths_are_null(string input) => Assert.Null(SourcePaths.Map(input, "C:", @"D:\"));

    [Fact]
    public void Per_user_variables_are_expanded_for_that_user()
    {
        var src = new FakeSystemSource(@"D:\");
        var bob = new UserProfile("S-1-5-21-1", "bob", @"D:\Users\bob", null, @"C:\Users\bob");
        Assert.Equal(@"D:\Users\bob\AppData\Roaming\x.exe", src.MapForUser(@"%APPDATA%\x.exe", bob));
        Assert.Equal(@"D:\Users\bob\AppData\Local\Temp\y.cmd", src.MapForUser(@"%TEMP%\y.cmd", bob));
        Assert.Null(src.MapPath(@"%APPDATA%\x.exe"));      // without a user it cannot be known
    }

    [Fact]
    public void Temporary_profile_uses_the_bak_twin_and_temp_profiles_are_skipped()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList", p => p
            .Key("S-1-5-21-1-2-3-1001", k => k.Exp("ProfileImagePath", @"C:\Users\TEMP").Num("State", 4))
            .Key("S-1-5-21-1-2-3-1001.bak", k => k.Exp("ProfileImagePath", @"C:\Users\bob"))
            .Key("S-1-5-21-1-2-3-1009", k => k.Exp("ProfileImagePath", @"C:\Users\TEMP.PC.002")));
        var users = SourcePaths.Profiles(sw.ToFake(), "C:", p => SourcePaths.Map(p, "C:", @"D:\"));
        var bob = Assert.Single(users);
        Assert.Equal("bob", bob.UserName);
        Assert.Equal("S-1-5-21-1-2-3-1001", bob.Sid);
        Assert.Equal(@"C:\Users\bob", bob.OriginalPath);
    }

    [Fact]
    public void Device_root_mapping() =>
        Assert.Equal(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Users\bob",
            SourcePaths.Map(@"C:\Users\bob", "C:", @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3"));

    [Fact]
    public void Control_set_from_select()
    {
        Assert.Equal("ControlSet002", SourcePaths.ControlSetName(RegSpec.Root().Key("Select", k => k.Num("Current", 2)).ToFake()));
        Assert.Equal("ControlSet001", SourcePaths.ControlSetName(RegSpec.Root().ToFake()));
    }

    [Fact]
    public void Profiles_skip_system_and_bak_and_map_paths()
    {
        var sw = RegSpec.Root().Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList", p => p
            .Key("S-1-5-18", k => k.Exp("ProfileImagePath", @"%systemroot%\system32\config\systemprofile"))
            .Key("S-1-5-21-1-2-3-1001", k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob"))
            .Key("S-1-5-21-1-2-3-1001.bak", k => k.Exp("ProfileImagePath", @"C:\Users\bob.old"))
            .Key("S-1-12-1-9-9-9-9", k => k.Str("ProfileImagePath", @"C:\Users\AzureAD_Ann"))
            .Key("S-1-5-21-1-2-3-1002", k => k.Str("ProfileImagePath", @"E:\Users\far")));
        var users = SourcePaths.Profiles(sw.ToFake(), "C:", p => SourcePaths.Map(p, "C:", @"D:\"));
        Assert.Equal(["AzureAD_Ann", "bob", "far"], users.Select(u => u.UserName).Order());
        Assert.Equal(@"D:\Users\bob", users.Single(u => u.UserName == "bob").ProfilePath);
        Assert.NotNull(users.Single(u => u.UserName == "far").Unavailable);
    }
}

public class OfflineSourceTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-offline").FullName + "\\";
    public void Dispose() => Directory.Delete(_root, true);

    void MiniWindows()
    {
        var config = Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "config")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Str("SystemRoot", @"C:\Windows").Str("ProductName", "Windows 10 Pro"))
            .Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1-2-3-1001", k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob")),
            Path.Combine(config, "SOFTWARE"));
        OffregHiveBuilder.Save(RegSpec.Root().Key("Select", k => k.Num("Current", 1)).Key(@"ControlSet001\Services\ekrn", k => k.Num("Start", 2)),
            Path.Combine(config, "SYSTEM"));
        var bob = Directory.CreateDirectory(Path.Combine(_root, "Users", "bob")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root().Key(@"Software\Microsoft\Windows\CurrentVersion\Run", k => k.Str("Thing", @"C:\x.exe")),
            Path.Combine(bob, "NTUSER.DAT"));
    }

    [Fact]
    public void Reads_an_offline_windows_tree()
    {
        MiniWindows();
        using var src = new OfflineSource(_root, runningWindowsDrive: @"Z:\");
        Assert.False(src.IsLive);
        Assert.Equal("C:", src.OriginalSystemDrive);
        Assert.Equal("ControlSet001", src.CurrentControlSet());
        var bob = Assert.Single(src.Users);
        Assert.Equal(Path.Combine(_root, "Users", "bob"), bob.ProfilePath);
        Assert.Equal(@"C:\x.exe", src.OpenHive(Hive.NtUser, bob)!.Open(@"Software\Microsoft\Windows\CurrentVersion\Run")!.GetString("Thing"));
        Assert.Equal(2, src.OpenHive(Hive.System)!.Open(@"ControlSet001\Services\ekrn")!.GetNumber("Start"));
        Assert.Equal(_root + @"Program Files\a.exe", src.MapPath(@"%ProgramFiles%\a.exe"));
    }

    [Fact]
    public void Folder_without_windows_is_rejected() =>
        Assert.Throws<SourceRejectedException>(() => new OfflineSource(_root, runningWindowsDrive: @"Z:\"));

    [Fact]
    public void The_running_windows_drive_is_rejected_however_it_is_named()
    {
        var windowsDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!;   // e.g. C:\
        var ex = Assert.Throws<SourceRejectedException>(() => new OfflineSource(windowsDrive));
        Assert.Contains("Windows you are running now", ex.Message);
        Assert.Throws<SourceRejectedException>(() => new OfflineSource(@"\\?\" + windowsDrive));
        Assert.Throws<SourceRejectedException>(() => new OfflineSource(@"\\.\" + windowsDrive));
    }

    [Fact]
    public void Device_path_roots_work_for_other_drives()
    {
        MiniWindows();
        using var src = new OfflineSource(@"\\?\" + _root);
        Assert.Single(src.Users);
    }

    [Fact]
    public void Confinement_blocks_links_that_leave_the_drive()
    {
        MiniWindows();
        var outside = Directory.CreateTempSubdirectory("pcporter-outside").FullName;
        try
        {
            File.WriteAllText(Path.Combine(outside, "host-secret.txt"), "host");
            var link = Path.Combine(_root, "Documents and Settings");
            using (var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                       $"/c mklink /J \"{link}\" \"{outside}\"") { CreateNoWindow = true, UseShellExecute = false })) p!.WaitForExit();
            Assert.True(Directory.Exists(link));

            using (SourceFiles.Confine(_root))
            {
                Assert.Throws<UnauthorizedAccessException>(() => SourceFiles.OpenRead(Path.Combine(link, "host-secret.txt")));
                Assert.Empty(SourceFiles.Files(link));
                using var ok = SourceFiles.OpenRead(Path.Combine(_root, "Windows", "System32", "config", "SOFTWARE"));   // inside: fine
            }
            using var unconfined = SourceFiles.OpenRead(Path.Combine(link, "host-secret.txt"));                         // no confinement: allowed
            Directory.Delete(link);
        }
        finally { Directory.Delete(outside, true); }
    }

    static void Junction(string link, string target)
    {
        using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false });
        p!.WaitForExit();
        Assert.True(Directory.Exists(link));
    }

    [Fact]
    public void Links_are_refused_before_their_target_is_opened()
    {
        // The target is locked exclusively: if PCPorter opened it, the error would be a sharing violation (IOException).
        // A link to \\server\share would make Windows connect and send credentials on open, so refusal must come first.
        var outside = Directory.CreateTempSubdirectory("pcporter-outside").FullName;
        var link = Path.Combine(_root, "Users");
        try
        {
            var secret = Path.Combine(outside, "secret.txt");
            File.WriteAllText(secret, "host");
            Junction(link, outside);
            using var locked = new FileStream(secret, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            using (SourceFiles.Confine(_root))
            {
                Assert.Throws<UnauthorizedAccessException>(() => SourceFiles.OpenRead(Path.Combine(link, "secret.txt")));
                Assert.False(SourceFiles.IsInside(Path.Combine(link, "secret.txt")));
                Assert.False(SourceFiles.IsInside(@"\\pcporter-nohost.invalid\share\x.txt"));
                Assert.Throws<UnauthorizedAccessException>(() => SourceFiles.OpenRead(@"\\pcporter-nohost.invalid\share\x.txt"));
                Assert.Throws<FileNotFoundException>(() => SourceFiles.OpenRead(Path.Combine(_root, "missing.txt")));
            }
        }
        finally { if (Directory.Exists(link)) Directory.Delete(link); Directory.Delete(outside, true); }
    }

    [Fact]
    public void Device_path_roots_stay_confined_and_fail_closed()
    {
        MiniWindows();
        var nt = PCPorter.Core.IO.FileIdentity.NtPath(_root);
        Assert.NotNull(nt);
        Assert.StartsWith(@"\Device\", nt);
        var deviceRoot = @"\\?\GLOBALROOT" + nt!.TrimEnd('\\') + "\\";       // the shape a shadow copy root has
        var outside = Directory.CreateTempSubdirectory("pcporter-outside").FullName;
        var link = Path.Combine(_root, "Documents and Settings");
        try
        {
            File.WriteAllText(Path.Combine(outside, "host-secret.txt"), "host");
            Junction(link, outside);
            using (SourceFiles.Confine(deviceRoot))
            {
                using (SourceFiles.OpenRead(deviceRoot + @"Windows\System32\config\SOFTWARE")) { }        // inside: fine
                Assert.True(SourceFiles.IsInside(deviceRoot + "Windows"));
                Assert.Throws<UnauthorizedAccessException>(() => SourceFiles.OpenRead(deviceRoot + @"Documents and Settings\host-secret.txt"));
                Assert.Empty(SourceFiles.Files(deviceRoot + "Documents and Settings"));
                Assert.False(SourceFiles.IsInside(deviceRoot + @"Windows\..\Documents and Settings"));
            }
            // A root that cannot be resolved confines to nothing.
            using (SourceFiles.Confine(@"\\?\GLOBALROOT\Device\PCPorterNoSuchVolume\"))
            {
                Assert.False(SourceFiles.IsInside(@"\\?\GLOBALROOT\Device\PCPorterNoSuchVolume\Windows"));
                Assert.Throws<UnauthorizedAccessException>(() => SourceFiles.OpenRead(Path.Combine(_root, "Windows", "System32", "config", "SOFTWARE")));
            }
        }
        finally { if (Directory.Exists(link)) Directory.Delete(link); Directory.Delete(outside, true); }
    }

    [Fact]
    public void Sam_and_security_hives_are_refused()
    {
        var sam = Path.Combine(_root, "SAM");
        File.WriteAllBytes(sam, [1]);
        Assert.Throws<UnauthorizedAccessException>(() => HiveParser.Parse(sam));
        Assert.Throws<UnauthorizedAccessException>(() => HiveParser.Parse(Path.Combine(_root, "SECURITY")));
    }

    [Fact]
    public void Corrupt_hive_is_a_problem_not_an_exception()
    {
        var p = Path.Combine(_root, "SOFTWARE");
        File.WriteAllBytes(p, "regf but not really a hive at all..."u8.ToArray());
        var r = HiveParser.Parse(p);
        Assert.Null(r.Root);
        Assert.NotNull(r.Problem);
    }

    [Fact]
    public void Parsing_never_modifies_the_hive_file()
    {
        MiniWindows();
        var file = Path.Combine(_root, "Windows", "System32", "config", "SOFTWARE");
        var before = File.ReadAllBytes(file);
        _ = HiveParser.Parse(file);
        Assert.Equal(before, File.ReadAllBytes(file));
    }

    /// <summary>A hive whose two sequence numbers differ (not closed cleanly), so its transaction logs are replayed.</summary>
    string DirtyHive()
    {
        MiniWindows();
        var file = Path.Combine(_root, "Windows", "System32", "config", "SOFTWARE");
        var bytes = File.ReadAllBytes(file);
        BitConverter.GetBytes(BitConverter.ToUInt32(bytes, 4) + 1).CopyTo(bytes, 4);     // primary sequence number
        uint sum = 0;                                                                      // header checksum (XOR of the first 127 dwords)
        for (int i = 0; i < 508; i += 4) sum ^= BitConverter.ToUInt32(bytes, i);
        BitConverter.GetBytes(sum).CopyTo(bytes, 508);
        File.WriteAllBytes(file, bytes);
        return file;
    }

    [Fact]
    public void Transaction_logs_are_read_through_source_files()
    {
        var file = DirtyHive();
        File.WriteAllBytes(file + ".LOG1", new byte[4096]);
        var reads = new List<string>();
        using (SourceFiles.Observe((kind, path) => { if (kind == "read") lock (reads) reads.Add(path); }))
        using (SourceFiles.Confine(_root))
            Assert.True(HiveParser.Parse(file).Dirty);
        Assert.Contains(file + ".LOG1", reads);
    }

    [Fact]
    public void An_oversized_transaction_log_is_not_replayed()
    {
        var file = DirtyHive();
        using (var fs = new FileStream(file + ".LOG1", FileMode.CreateNew)) fs.SetLength(HiveParser.MaxLogBytes + 1);
        var r = HiveParser.Parse(file);
        Assert.True(r.Dirty);
        Assert.False(r.Replayed);
        Assert.NotNull(r.Root);
    }
}

public class LiveSourceTests
{
    [Fact]
    [Trait("Category", "Live")]
    public void Reads_this_pcs_registry_read_only()
    {
        using var src = new LiveSource();
        Assert.True(src.IsLive);
        Assert.NotNull(src.OpenHive(Hive.Software)!.Open(@"Microsoft\Windows NT\CurrentVersion")!.GetString("CurrentBuild"));
        Assert.StartsWith("ControlSet", src.CurrentControlSet());
        Assert.NotEmpty(src.Users);
    }

    [Fact]
    public void Process_runner_refuses_programs_outside_system32() =>
        Assert.Throws<UnauthorizedAccessException>(() => new ProcessRunner().Run(@"C:\Users\Public\evil.exe", [], TimeSpan.FromSeconds(1)));

    [Fact]
    public void Helpers_get_a_clean_environment()
    {
        Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", @"C:\Users\Public\hook.dll");
        try
        {
            var r = new ProcessRunner().Run("cmd.exe", ["/d", "/c", "set"], TimeSpan.FromSeconds(10));
            Assert.Equal(0, r.ExitCode);
            Assert.DoesNotContain("DOTNET_STARTUP_HOOKS", r.StdOut);
            Assert.DoesNotContain("PSModulePath", r.StdOut, StringComparison.OrdinalIgnoreCase);
            var path = r.StdOut.Split('\n').Single(l => l.StartsWith("Path=", StringComparison.OrdinalIgnoreCase)).Trim();
            Assert.StartsWith("Path=" + Environment.SystemDirectory + ";", path, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(@"\Users\", path, StringComparison.OrdinalIgnoreCase);
        }
        finally { Environment.SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", null); }
    }
}
