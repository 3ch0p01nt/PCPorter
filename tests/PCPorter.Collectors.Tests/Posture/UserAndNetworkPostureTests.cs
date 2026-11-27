using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PCPorter.Collectors.Posture;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Posture;

public class UserAndNetworkPostureTests
{
    static Dictionary<string, RegSpec> Users(RegSpec bob, RegSpec? ann = null)
    {
        var d = new Dictionary<string, RegSpec> { [PT.Bob.Sid] = bob };
        if (ann is not null) d[PT.Ann.Sid] = ann;
        return d;
    }

    static RegSpec ProfileList() => RegSpec.Root()
        .Key($@"Microsoft\Windows NT\CurrentVersion\ProfileList\{PT.Bob.Sid}", k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob"))
        .Key($@"Microsoft\Windows NT\CurrentVersion\ProfileList\{PT.Ann.Sid}", k => k.Exp("ProfileImagePath", @"C:\Users\ann"));

    // ---- 2. Backups ----
    static RegSpec Kfm(string userFolder, string desktop) => RegSpec.Root()
        .Key(@"Software\Microsoft\OneDrive\Accounts\Personal", k => k.Str("UserFolder", userFolder))
        .Key(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", k => k
            .Exp("Desktop", desktop).Exp("Personal", @"%USERPROFILE%\Documents").Exp("My Pictures", @"%USERPROFILE%\Pictures"));

    [Fact]
    public void Backup_onedrive_known_folder_move()
    {
        var c = PT.Check(PT.Offline(ProfileList(), users: Users(Kfm(@"C:\Users\bob\OneDrive", @"%USERPROFILE%\OneDrive\Desktop"))), PostureIds.Backup);
        Assert.Equal(PostureStatus.Good, c.Status);
        Assert.Contains("[Desktop]", c.Evidence);
    }

    [Fact]
    public void Backup_onedrive_without_folder_move_is_attention()
    {
        // OneDrive is signed in, but Desktop is not inside it; "OneDrive2" must not count as inside "OneDrive".
        var c = PT.Check(PT.Offline(ProfileList(), users: Users(Kfm(@"C:\Users\bob\OneDrive", @"C:\Users\bob\OneDrive2\Desktop"))), PostureIds.Backup);
        Assert.Equal(PostureStatus.Attention, c.Status);
        Assert.False(string.IsNullOrWhiteSpace(c.Advice));
    }

    [Fact]
    public void Backup_file_history_counts_and_partial_users_are_reported()
    {
        var fh = RegSpec.Root().Key(@"Software\Microsoft\Windows\CurrentVersion\FileHistory", k =>
            k.QNum("ProtectedUpToTime", (ulong)new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero).ToFileTime()));
        var good = PT.Check(PT.Offline(ProfileList(), users: Users(fh)), PostureIds.Backup);
        Assert.Equal(PostureStatus.Good, good.Status);
        Assert.Contains("ProtectedUpToTime=2026-11-01", good.Evidence);

        var mixed = PT.Check(PT.Offline(ProfileList(), users: Users(fh, RegSpec.Root())), PostureIds.Backup);
        Assert.Equal(PostureStatus.Attention, mixed.Status);
        Assert.Contains("1 of 2", mixed.Finding);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.Backup).Status);
    }

    // ---- 4. Defender ----
    static FakeWmiClient Mp(string mode, bool tamper, bool rtp, long age) => new FakeWmiClient().Add(AccountChecks.DefenderNamespace, "MSFT_MpComputerStatus",
        PT.Row(("AMRunningMode", mode), ("IsTamperProtected", tamper), ("RealTimeProtectionEnabled", rtp), ("AntivirusSignatureAge", (uint)age)));

    [Fact]
    public void Defender_live()
    {
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Live(), PostureIds.Defender, Mp("Normal", true, true, 0)).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Live(), PostureIds.Defender, Mp("Normal", false, true, 0)).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Live(), PostureIds.Defender, Mp("Normal", true, true, 30)).Status);
        Assert.Equal(PostureStatus.Risk, PT.Check(PT.Live(), PostureIds.Defender, Mp("Normal", true, false, 0)).Status);
        Assert.Equal(PostureStatus.NotApplicable, PT.Check(PT.Live(), PostureIds.Defender, Mp("Passive Mode", false, false, 99)).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Live(), PostureIds.Defender,
            new FakeWmiClient().Fail(AccountChecks.DefenderNamespace, "MSFT_MpComputerStatus", WmiOutcome.AccessDenied)).Status);
    }

    [Fact]
    public void Defender_offline_tamper_protection()
    {
        static RegSpec Wd(Action<RegSpec> f) => RegSpec.Root().Key(@"Microsoft\Windows Defender", f);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(Wd(k => k.Key("Features", f => f.Num("TamperProtection", 5)))), PostureIds.Defender).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(Wd(k => k.Key("Features", f => f.Num("TamperProtection", 4)))), PostureIds.Defender).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(Wd(_ => { })), PostureIds.Defender).Status);
        Assert.Equal(PostureStatus.NotApplicable, PT.Check(PT.Offline(Wd(k => k.Num("PassiveMode", 1))), PostureIds.Defender).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.Defender).Status);
        Assert.Empty(new FakeWmiClient().Queries);
    }

    [Fact]
    public void Offline_scan_never_queries_wmi()
    {
        var wmi = new FakeWmiClient();
        PT.Run(PT.Offline(), wmi);
        Assert.Empty(wmi.Queries);
    }

    // ---- 6. Root certificates ----
    static byte[] Blob(byte[] der)
    {
        var b = new byte[12 + der.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 32);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), (uint)der.Length);
        der.CopyTo(b, 12);
        return b;
    }

    [Fact]
    public void Root_certificates_added_for_a_user_need_attention()
    {
        using var key = ECDsa.Create();
        using var cert = new CertificateRequest("CN=Test Root", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var bob = RegSpec.Root().Key(@"Software\Microsoft\SystemCertificates\Root\Certificates\" + cert.Thumbprint, k => k.Bin("Blob", Blob(cert.RawData)));
        var sw = RegSpec.Root().Key(@"Microsoft\SystemCertificates\ROOT\Certificates", k => k.Key("A1").Key("B2").Key("C3"));
        var c = PT.Check(PT.Offline(sw, users: Users(bob)), PostureIds.RootCertificates);
        Assert.Equal(PostureStatus.Attention, c.Status);
        Assert.Contains("CN=Test Root", c.Evidence);
        Assert.Contains("Machine root store: 3", c.Evidence);

        var clean = PT.Check(PT.Offline(sw, users: Users(RegSpec.Root())), PostureIds.RootCertificates);
        Assert.Equal(PostureStatus.Good, clean.Status);
        Assert.Null(UserChecks.Subject([1, 2, 3]));
        Assert.Null(UserChecks.Subject(Blob([0x30, 0x01])));
    }

    // ---- 7. Auto-logon ----
    static RegSpec Winlogon(string? auto, bool password) => RegSpec.Root().Key(AccountChecks.WinlogonPath, k =>
    {
        if (auto is not null) k.Str("AutoAdminLogon", auto);
        k.Str("DefaultUserName", "bob");
        if (password) k.Str("DefaultPassword", "hunter2-secret");
    });

    [Fact]
    public void Auto_logon_states()
    {
        var on = PT.Check(PT.Offline(Winlogon("1", true)), PostureIds.AutoLogon);
        Assert.Equal(PostureStatus.Risk, on.Status);
        Assert.Contains("DefaultPassword exists", on.Evidence);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(Winlogon("0", true)), PostureIds.AutoLogon).Status);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(Winlogon("0", false)), PostureIds.AutoLogon).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.AutoLogon).Status);
    }

    [Fact]
    public void Default_password_data_is_never_read()
    {
        var reads = new List<string>();
        using var src = new SpySource(PT.Live(Winlogon("1", true), PT.System()), reads);
        var (checks, _, _) = PT.Run(src, new FakeWmiClient());
        Assert.Contains(reads, r => r.EndsWith("|AutoAdminLogon", StringComparison.Ordinal));   // the spy works
        Assert.DoesNotContain(reads, r => r.EndsWith("|DefaultPassword", StringComparison.OrdinalIgnoreCase));
        Assert.All(checks, c => Assert.DoesNotContain("hunter2", c.Evidence + c.Finding + c.Advice));
    }

    // ---- 8. Local accounts (live only) ----
    [Fact]
    public void Local_accounts_live()
    {
        var wmi = new FakeWmiClient()
            .Add(@"root\cimv2", "Win32_GroupUser",
                PT.Row(("PartComponent", "\\\\PC\\root\\cimv2:Win32_UserAccount.Domain=\"PC\",Name=\"bob\"")),
                PT.Row(("PartComponent", "garbage")),
                PT.Row(("PartComponent", "\\\\PC\\root\\cimv2:Win32_Group.Domain=\"CORP\",Name=\"Domain Admins\"")))
            .Add(@"root\cimv2", "Win32_Group", PT.Row(("Name", "Administratoren"), ("Domain", "PC")))
            .Add(@"root\cimv2", "Win32_UserAccount",
                PT.Row(("Name", "bob"), ("SID", "S-1-5-21-1-2-3-1001"), ("Disabled", false), ("PasswordRequired", true)),
                PT.Row(("Name", "guest"), ("SID", "S-1-5-21-1-2-3-501"), ("Disabled", true), ("PasswordRequired", false)),
                PT.Row(("Name", "kid"), ("SID", "S-1-5-21-1-2-3-1003"), ("Disabled", false), ("PasswordRequired", false)));
        var c = PT.Check(PT.Live(), PostureIds.LocalAccounts, wmi);
        Assert.Equal(PostureStatus.Attention, c.Status);
        Assert.Contains("may have no password", c.Finding);
        Assert.Contains("kid", c.Finding);
        Assert.DoesNotContain("guest", c.Finding);
        Assert.Contains("Members: bob, group CORP\\Domain Admins", c.Evidence);
        Assert.Contains(wmi.Queries, q => q.Contains("Name='Administratoren'", StringComparison.Ordinal));
        Assert.True(c.LiveOnly);

        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.LocalAccounts).Status);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Live(), PostureIds.LocalAccounts, new FakeWmiClient()).Status);
    }

    [Fact]
    public void Local_accounts_all_with_passwords_is_good()
    {
        var wmi = new FakeWmiClient().Add(@"root\cimv2", "Win32_UserAccount",
            PT.Row(("Name", "bob"), ("SID", "S-1-5-21-1-2-3-1001"), ("Disabled", false), ("PasswordRequired", true)),
            PT.Row(("Name", "Administrator"), ("SID", "S-1-5-21-1-2-3-500"), ("Disabled", true), ("PasswordRequired", true)));
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Live(), PostureIds.LocalAccounts, wmi).Status);
    }

    [Theory]
    [InlineData("\\\\PC\\root\\cimv2:Win32_UserAccount.Domain=\"PC\",Name=\"bob\"", "Win32_UserAccount", "PC", "bob")]
    [InlineData("Win32_Group.Domain=\"D\",Name=\"G x\"", "Win32_Group", "D", "G x")]
    public void Member_paths_parse(string path, string cls, string domain, string name) =>
        Assert.Equal((cls, domain, name), AccountChecks.ParseMember(path));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Win32_UserAccount.Name=\"bob\"")]
    [InlineData("Domain=\"PC\",Name=\"bob\"")]
    public void Bad_member_paths_are_null(string? path) => Assert.Null(AccountChecks.ParseMember(path));

    // ---- 9. Forced browser extensions ----
    const string ExtA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExtB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ExtC = "cccccccccccccccccccccccccccccccc";

    [Fact]
    public void Forced_extensions_from_outside_the_stores()
    {
        var sw = RegSpec.Root()
            .Key(@"Policies\Google\Chrome\ExtensionInstallForcelist", k => k
                .Str("1", ExtA + ";https://clients2.google.com/service/update2/crx")
                .Str("2", ExtB + ";https://evil.example/update.xml"))
            .Key(@"Policies\Microsoft\Edge\ExtensionInstallForcelist", k => k.Str("1", ExtC));
        var bob = RegSpec.Root().Key(@"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist", k => k.Str("1", ExtA + ";http://edge.microsoft.com/x"));
        var checks = PT.Run(PT.Offline(sw, users: Users(bob))).Checks;
        var summary = checks.Single(c => c.Id == PostureIds.BrowserExtensions);
        Assert.Equal(PostureStatus.Attention, summary.Status);
        var per = checks.Where(c => c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal)).ToList();
        Assert.Equal(2, per.Count);                                          // evil.example and plain-http edge URL
        Assert.Contains(per, c => c.Id == $"browser-extension:chrome:machine:{ExtB}");
        Assert.Contains(per, c => c.Id == $"browser-extension:edge:user-bob:{ExtA}");
        Assert.All(per, c => Assert.Equal(PostureStatus.Attention, c.Status));
    }

    [Fact]
    public void ExtensionSettings_and_Firefox_policies_count_too()
    {
        var sw = RegSpec.Root()
            .Key(@"Policies\Google\Chrome", k => k.Str("ExtensionSettings",
                $$$"""{"{{{ExtA}}}":{"installation_mode":"force_installed","update_url":"https://evil.example/u.xml"},"{{{ExtB}}}":{"installation_mode":"blocked"},"*":{"installation_mode":"allowed"}}"""))
            .Key(@"Policies\Mozilla\Firefox\Extensions\Install", k => k.Str("1", "https://evil.example/x.xpi").Str("2", "https://addons.mozilla.org/firefox/downloads/file/1/ublock.xpi"));
        var checks = PT.Run(PT.Offline(sw)).Checks;
        Assert.Equal(PostureStatus.Attention, checks.Single(c => c.Id == PostureIds.BrowserExtensions).Status);
        var per = checks.Where(c => c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal)).Select(c => c.Id).ToList();
        Assert.Equal(2, per.Count);                                          // the blocked one and the Mozilla-store one are fine
        Assert.Contains($"browser-extension:chrome:machine:{ExtA}", per);
        Assert.Contains(per, i => i.StartsWith("browser-extension:firefox:machine:", StringComparison.Ordinal));
    }

    [Fact]
    public void Store_only_extensions_are_good()
    {
        var sw = RegSpec.Root().Key(@"Policies\Microsoft\Edge\ExtensionInstallForcelist", k => k.Str("1", ExtA + ";https://edge.microsoft.com/extensionwebstorebase/v1/crx"));
        var checks = PT.Run(PT.Offline(sw)).Checks;
        Assert.Equal(PostureStatus.Good, checks.Single(c => c.Id == PostureIds.BrowserExtensions).Status);
        Assert.DoesNotContain(checks, c => c.Id.StartsWith(PostureIds.BrowserExtensionPrefix, StringComparison.Ordinal));
        Assert.Equal(PostureStatus.Good, PT.Run(PT.Offline(RegSpec.Root())).Checks.Single(c => c.Id == PostureIds.BrowserExtensions).Status);
    }

    // ---- 10. Proxy, DNS, hosts ----
    [Fact]
    public void Proxy_settings()
    {
        static RegSpec Inet(Action<RegSpec> f) => RegSpec.Root().Key(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", f);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(users: Users(Inet(k => k.Num("ProxyEnable", 0).Str("ProxyServer", "old:8080")))), PostureIds.Proxy).Status);
        Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(users: Users(Inet(k => k.Num("ProxyEnable", 1).Str("ProxyServer", "10.0.0.1:3128")))), PostureIds.Proxy).Status);
        var pac = PT.Check(PT.Offline(users: Users(Inet(k => k.Str("AutoConfigURL", "http://wpad.example/proxy.pac")))), PostureIds.Proxy);
        Assert.Equal(PostureStatus.Attention, pac.Status);
        Assert.Contains("proxy.pac", pac.Evidence);
        Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(), PostureIds.Proxy).Status);
    }

    [Fact]
    public void Manual_dns()
    {
        static RegSpec Ifs(string servers) => PT.System(c => c.Key(@"Services\Tcpip\Parameters\Interfaces\{1111}", k => k.Str("NameServer", servers))
            .Key(@"Services\Tcpip\Parameters\Interfaces\{2222}", k => k.Str("NameServer", "")));
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: PT.System(c => c.Key(@"Services\Tcpip\Parameters"))), PostureIds.Dns).Status);
        Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: Ifs("1.1.1.1,192.168.1.1")), PostureIds.Dns).Status);
        var odd = PT.Check(PT.Offline(system: Ifs("203.0.113.7 8.8.8.8")), PostureIds.Dns);
        Assert.Equal(PostureStatus.Attention, odd.Status);
        Assert.Contains("203.0.113.7", odd.Finding);
        Assert.DoesNotContain("8.8.8.8", odd.Finding);
    }

    [Fact]
    public void Hosts_file()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-posture").FullName;
        try
        {
            var etc = Path.Combine(root, @"Windows\System32\drivers\etc");
            Directory.CreateDirectory(etc);
            var hosts = Path.Combine(etc, "hosts");

            File.WriteAllText(hosts, "# comment\n127.0.0.1 localhost\n::1 localhost\n");
            Assert.Equal(PostureStatus.Good, PT.Check(PT.Offline(system: PT.System(), root: root), PostureIds.HostsFile).Status);

            File.WriteAllText(hosts, "0.0.0.0 ads.example tracker.example # blocker\n");
            var block = PT.Check(PT.Offline(system: PT.System(), root: root), PostureIds.HostsFile);
            Assert.Equal(PostureStatus.Good, block.Status);
            Assert.Contains("2 name", block.Finding);

            File.WriteAllText(hosts, "203.0.113.5 www.mybank.example\n\t# 1.2.3.4 ignored.example\n");
            var redirect = PT.Check(PT.Offline(system: PT.System(), root: root), PostureIds.HostsFile);
            Assert.Equal(PostureStatus.Attention, redirect.Status);
            Assert.Contains("www.mybank.example -> 203.0.113.5", redirect.Evidence);
            Assert.DoesNotContain("ignored.example", redirect.Evidence);

            var moved = PT.System(c => c.Key(@"Services\Tcpip\Parameters", k => k.Exp("DataBasePath", @"C:\Temp\etc")));
            Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(system: moved, root: root), PostureIds.HostsFile).Status);
            var standard = PT.System(c => c.Key(@"Services\Tcpip\Parameters", k => k.Exp("DataBasePath", @"%SystemRoot%\System32\drivers\etc")));
            Assert.Equal(PostureStatus.Attention, PT.Check(PT.Offline(system: standard, root: root), PostureIds.HostsFile).Status);  // still the redirect

            File.Delete(hosts);
            Assert.Equal(PostureStatus.Unknown, PT.Check(PT.Offline(system: standard, root: root), PostureIds.HostsFile).Status);
        }
        finally { Directory.Delete(root, true); }
    }
}
