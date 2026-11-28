using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using PCPorter.Core.Case;

namespace PCPorter.Core.Tests.Case;

public class OtherPcCasesTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-otherpc").FullName;
    public void Dispose()
    {
        RemoveJunctions(_root);                    // first, so deleting never reaches through one
        Directory.Delete(_root, true);
    }

    static void RemoveJunctions(string dir)
    {
        foreach (var d in Directory.GetDirectories(dir))
            if (new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(d);
            else RemoveJunctions(d);
    }

    static readonly DateTimeOffset Now = new(2026, 11, 27, 10, 0, 0, TimeSpan.Zero);

    /// <summary>A test account's SID: never a real account, so the test proves the rule without granting anyone anything.</summary>
    static readonly SecurityIdentifier TestSid = new("S-1-5-21-1111111111-2222222222-3333333333-1001");

    /// <summary>A case as PCPorter makes it (private ACL), with a report and a file in a subfolder.</summary>
    string MakeCase(string pc = "OLD-PC", DateTimeOffset? when = null, string outRoot = "")
    {
        var c = CaseFolder.Create(outRoot.Length == 0 ? _root : outRoot, when ?? Now, pc, _ => null).Path;
        File.WriteAllText(Path.Combine(c, "case.db"), "");
        File.WriteAllText(Path.Combine(c, "HealthReport.html"), "<html></html>");
        CaseFolder.CreatePrivate(Path.Combine(c, "Thumbnails"));
        File.WriteAllText(Path.Combine(c, "Thumbnails", "Thumbnails.html"), "<html></html>");
        return c;
    }

    static void Junction(string link, string target)
    {
        using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false });
        p!.WaitForExit();
        Assert.True(Directory.Exists(link));
    }

    static IEnumerable<FileSystemAccessRule> Rules(FileSystemSecurity sec) =>
        sec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();

    [Fact]
    public void Finds_case_folders_with_pc_date_and_reports_and_ignores_look_alikes()
    {
        var older = MakeCase("OLD-PC", Now.AddDays(-1));
        var newer = MakeCase("OLD-PC", Now);
        var pcporter = Path.Combine(_root, "PCPorter");
        Directory.CreateDirectory(Path.Combine(pcporter, "OLD-PC_20261127T100000Z_zzzzzz"));                    // not hex
        Directory.CreateDirectory(Path.Combine(pcporter, "Holiday photos"));
        Directory.CreateDirectory(Path.Combine(pcporter, "OLD-PC_20261127T110000Z_abcdef"));                    // no case.db
        Directory.CreateDirectory(Path.Combine(_root, "Other", "OLD-PC_20261127T100000Z_abcdef"));              // not in a PCPorter folder
        File.WriteAllText(Path.Combine(_root, "Other", "OLD-PC_20261127T100000Z_abcdef", "case.db"), "");

        var found = OtherPcCases.FindIn(_root);

        Assert.Equal([newer, older], found.Cases.Select(c => c.Path));
        var c = found.Cases[0];
        Assert.Equal("OLD-PC", c.ComputerName);
        Assert.Equal(Now, c.CreatedUtc);
        Assert.Equal(["Health and security", "Images viewed"], c.Reports);
        Assert.True(c.Readable);
        Assert.Contains("OLD-PC", c.ToString());
        Assert.Contains("Health and security, Images viewed", c.ToString());
        Assert.Empty(found.Unreadable);
    }

    [Fact]
    public void The_same_cases_are_found_from_the_pcporter_folder_or_the_case_itself()
    {
        var c = MakeCase();
        Assert.Equal([c], OtherPcCases.FindIn(Path.Combine(_root, "PCPorter")).Cases.Select(x => x.Path));
        Assert.Equal([c], OtherPcCases.FindIn(c).Cases.Select(x => x.Path));
    }

    [Fact]
    public void A_pcporter_folder_reached_through_a_junction_is_not_searched()
    {
        var elsewhere = Path.Combine(_root, "elsewhere");
        MakeCase(outRoot: elsewhere);
        var sneaky = Directory.CreateDirectory(Path.Combine(_root, "sneaky")).FullName;
        Junction(Path.Combine(sneaky, "PCPorter"), Path.Combine(elsewhere, "PCPorter"));   // sneaky\PCPorter -> elsewhere\PCPorter
        Assert.Single(OtherPcCases.FindIn(elsewhere).Cases);
        Assert.Empty(OtherPcCases.FindIn(sneaky).Cases);
    }

    [Fact]
    public void Grant_gives_read_to_the_account_on_everything_inside_and_keeps_the_private_rules()
    {
        var c = MakeCase();
        var before = Rules(new DirectoryInfo(c).GetAccessControl()).Select(r => r.IdentityReference).ToHashSet();

        OtherPcCases.GrantRead(c, TestSid);

        var sec = new DirectoryInfo(c).GetAccessControl();
        Assert.True(sec.AreAccessRulesProtected);                                                // still not opened to everyone
        var rule = Assert.Single(Rules(sec), r => r.IdentityReference.Equals(TestSid));
        Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
        Assert.True(rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute));
        Assert.False(rule.FileSystemRights.HasFlag(FileSystemRights.WriteData));
        Assert.Subset(Rules(sec).Select(r => r.IdentityReference).ToHashSet(), before);         // nothing removed
        Assert.DoesNotContain(Rules(sec), r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.WorldSid, null)));

        // Files and folders already inside inherit it (the report, and the gallery in its subfolder).
        foreach (var inside in new[] { Path.Combine(c, "HealthReport.html"), Path.Combine(c, "Thumbnails", "Thumbnails.html") })
            Assert.Contains(Rules(new FileInfo(inside).GetAccessControl()), r => r.IdentityReference.Equals(TestSid)
                && r.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute));

        // The PCPorter folder above is not changed.
        Assert.DoesNotContain(Rules(new DirectoryInfo(Path.Combine(_root, "PCPorter")).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
    }

    [Fact]
    public void Can_read_is_true_for_the_account_that_made_it_and_after_a_grant()
    {
        var c = MakeCase();
        Assert.True(OtherPcCases.CanRead(c, WindowsIdentity.GetCurrent().User!));                // made by this account
        Assert.False(OtherPcCases.CanRead(c, TestSid));                                          // another PC's account
        OtherPcCases.GrantRead(c, TestSid);
        Assert.True(OtherPcCases.CanRead(c, TestSid));
        Assert.False(OtherPcCases.CanRead(Path.Combine(_root, "missing"), TestSid));
    }

    [Fact]
    public void Results_on_a_drive_without_permissions_are_readable_by_anyone()
    {
        // exFAT/FAT32 keep no permissions: there is nothing to grant, so never ask to "let this account read them".
        var c = MakeCase();
        Assert.False(OtherPcCases.CanRead(c, TestSid));
        Assert.True(OtherPcCases.CanRead(c, TestSid, _ => new VolumeFormat("exFAT", false)));
    }

    [Fact]
    public void Grant_for_the_current_user_lets_them_read_the_report()
    {
        var c = MakeCase();
        OtherPcCases.GrantRead(c, WindowsIdentity.GetCurrent().User!);
        Assert.Equal("<html></html>", File.ReadAllText(Path.Combine(c, "HealthReport.html")));
    }

    [Fact]
    public void Grant_refuses_anything_that_is_not_a_case_folder_and_changes_nothing()
    {
        var c = MakeCase();
        var noDb = Directory.CreateDirectory(Path.Combine(_root, "PCPorter", "OLD-PC_20261127T110000Z_abcdef")).FullName;
        var wrongPlace = Directory.CreateDirectory(Path.Combine(_root, "Docs", "OLD-PC_20261127T100000Z_abcdef")).FullName;
        File.WriteAllText(Path.Combine(wrongPlace, "case.db"), "");

        foreach (var path in new[] { _root, Path.Combine(_root, "PCPorter"), noDb, wrongPlace, Path.Combine(c, "case.db"),
                     Path.Combine(c, "Thumbnails"), Path.Combine(c, "..", Path.GetFileName(c)), "relative\\PCPorter\\x", "", @"\\server\share\PCPorter\OLD-PC_20261127T100000Z_abcdef" })
            Assert.Throws<CaseLocationRejectedException>(() => OtherPcCases.GrantRead(path, TestSid));

        foreach (var folder in new[] { _root, c, noDb, wrongPlace })
            Assert.DoesNotContain(Rules(new DirectoryInfo(folder).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
    }

    [Fact]
    public void Grant_refuses_a_case_folder_that_is_a_junction()
    {
        var real = MakeCase(outRoot: Path.Combine(_root, "real"));
        var pcporter = Directory.CreateDirectory(Path.Combine(_root, "PCPorter")).FullName;
        var link = Path.Combine(pcporter, Path.GetFileName(real));
        Junction(link, real);
        Assert.Throws<CaseLocationRejectedException>(() => OtherPcCases.GrantRead(link, TestSid));
        Assert.Empty(OtherPcCases.FindIn(_root).Cases);
        Assert.DoesNotContain(Rules(new DirectoryInfo(real).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
    }

    [Fact]
    public void Grant_refuses_a_case_with_a_link_inside_so_nothing_outside_is_changed()
    {
        var c = MakeCase();
        var outside = Directory.CreateDirectory(Path.Combine(_root, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "x");
        Junction(Path.Combine(c, "Thumbnails", "planted"), outside);

        var ex = Assert.Throws<CaseLocationRejectedException>(() => OtherPcCases.GrantRead(c, TestSid));
        Assert.Contains("planted", ex.Message);
        Assert.DoesNotContain(Rules(new DirectoryInfo(c).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
        Assert.DoesNotContain(Rules(new FileInfo(Path.Combine(outside, "secret.txt")).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
    }

    [Fact]
    public void Grant_refuses_a_hard_link_inside()
    {
        var c = MakeCase();
        var outside = Path.Combine(_root, "outside.txt");
        File.WriteAllText(outside, "x");
        using (var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                   $"/c mklink /H \"{Path.Combine(c, "linked.txt")}\" \"{outside}\"") { CreateNoWindow = true, UseShellExecute = false }))
            p!.WaitForExit();
        Assert.True(File.Exists(Path.Combine(c, "linked.txt")));
        Assert.Throws<CaseLocationRejectedException>(() => OtherPcCases.GrantRead(c, TestSid));
        Assert.DoesNotContain(Rules(new FileInfo(outside).GetAccessControl()), r => r.IdentityReference.Equals(TestSid));
    }
}
