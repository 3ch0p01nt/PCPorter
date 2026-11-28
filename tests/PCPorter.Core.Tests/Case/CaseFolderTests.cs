using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using PCPorter.Core.Case;

namespace PCPorter.Core.Tests.Case;

public class CaseFolderTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-case").FullName;
    public void Dispose()
    {
        foreach (var d in Directory.EnumerateDirectories(_root))
            if (new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(d);
        Directory.Delete(_root, true);
    }

    static readonly DateTimeOffset Now = new(2026, 11, 27, 10, 0, 0, TimeSpan.Zero);
    static string? NoEnv(string _) => null;

    [Fact]
    public void Case_folder_is_private_unique_and_not_indexed()
    {
        var a = CaseFolder.Create(_root, Now, "BOB-PC", NoEnv);
        var b = CaseFolder.Create(_root, Now, "BOB-PC", NoEnv);
        Assert.NotEqual(a.Path, b.Path);                                   // same second, still unique
        Assert.StartsWith(Path.Combine(_root, "PCPorter", "BOB-PC_20261127T100000Z_"), a.Path);

        var rules = new DirectoryInfo(a.Path).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToList();
        var allowed = rules.Select(r => r.IdentityReference).Cast<SecurityIdentifier>().ToHashSet();
        Assert.Subset(CaseFolder.PrivateSids().ToHashSet(), allowed);
        Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), allowed);
        Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), allowed);
        Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.WorldSid, null), allowed);
        Assert.True(new DirectoryInfo(a.Path).Attributes.HasFlag(FileAttributes.NotContentIndexed));

        // Files created inside inherit the private ACL.
        var file = Path.Combine(a.Path, "x.txt");
        File.WriteAllText(file, "x");
        var fileSids = new FileInfo(file).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().Select(r => r.IdentityReference).ToHashSet();
        Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), fileSids);
    }

    [Theory]
    [InlineData("exFAT")]
    [InlineData("FAT32")]
    public void A_drive_without_permissions_gets_plain_folders_and_a_warning(string format)
    {
        // Setting an ACL on exFAT/FAT32 fails; the probe plays that drive, so no ACL call may be made.
        var probed = new List<string>();
        VolumeFormat? Fat(string path) { probed.Add(path); return new VolumeFormat(format, KeepsPermissions: false); }
        var a = CaseFolder.Create(_root, Now, "BOB-PC", NoEnv, Fat);

        Assert.True(Directory.Exists(a.Path));
        Assert.False(new DirectoryInfo(a.Path).GetAccessControl().AreAccessRulesProtected);      // inherited: no ACL was set
        Assert.False(new DirectoryInfo(Path.Combine(_root, "PCPorter")).GetAccessControl().AreAccessRulesProtected);
        var warning = Assert.Single(a.Warnings);
        Assert.Contains(format, warning);
        Assert.Contains("Anyone with the drive can open the case", warning);
        Assert.Contains(a.Path, probed);
    }

    [Fact]
    public void An_ntfs_drive_gets_the_private_acl_and_no_warning()
    {
        var a = CaseFolder.Create(_root, Now, "BOB-PC", NoEnv, _ => new VolumeFormat("NTFS", KeepsPermissions: true));
        Assert.Empty(a.Warnings);
        Assert.True(new DirectoryInfo(a.Path).GetAccessControl().AreAccessRulesProtected);
    }

    [Fact]
    public void The_real_probe_reads_the_temp_drive_as_ntfs()
    {
        var f = CaseFolder.FormatOf(_root);
        Assert.NotNull(f);
        Assert.Equal(f.Name is "NTFS" or "ReFS", f.KeepsPermissions);
    }

    [Fact]
    public void The_work_folder_is_per_case_in_pcporters_own_folder_not_in_the_case()
    {
        var a = CaseFolder.Create(_root, Now, "BOB-PC", NoEnv);
        var work = CaseFolder.CreateWork(a.Path);
        try
        {
            Assert.Equal(Path.Combine(PCPorter.Core.Security.AppFolders.For("work"), Path.GetFileName(a.Path)), work);
            Assert.False(work.StartsWith(_root, StringComparison.OrdinalIgnoreCase));
            Assert.True(new DirectoryInfo(work).GetAccessControl().AreAccessRulesProtected);
            var allowed = new DirectoryInfo(work).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>().Select(r => r.IdentityReference).Cast<SecurityIdentifier>().ToHashSet();
            Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), allowed);
        }
        finally { Directory.Delete(work, true); }
    }

    [Fact]
    public void Synced_folder_is_rejected()
    {
        var ex = Assert.Throws<CaseLocationRejectedException>(() =>
            CaseFolder.Create(Path.Combine(_root, "OneDrive - Contoso", "Cases"), Now, "PC", NoEnv));
        Assert.Contains("OneDrive", ex.Message);
    }

    [Fact]
    public void Junction_is_rejected()
    {
        var target = Directory.CreateDirectory(Path.Combine(_root, "elsewhere")).FullName;
        var link = Path.Combine(_root, "link");
        using (var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                   $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false }))
            p!.WaitForExit();
        Assert.True(Directory.Exists(link));
        Assert.Throws<CaseLocationRejectedException>(() => CaseFolder.Create(link, Now, "PC", NoEnv));
    }

    [Fact]
    public void Nothing_is_created_through_a_junction()
    {
        var target = Directory.CreateDirectory(Path.Combine(_root, "elsewhere")).FullName;
        var link = Path.Combine(_root, "link");
        CaseLocationTests.Junction(link, target);
        Assert.Throws<CaseLocationRejectedException>(() => CaseFolder.Create(Path.Combine(link, "new", "cases"), Now, "PC", NoEnv));
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));          // no folder was made in the link's target
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative")]
    public void Empty_or_relative_folder_is_a_clear_rejection(string outRoot)
    {
        var ex = Assert.Throws<CaseLocationRejectedException>(() => CaseFolder.Create(outRoot, Now, "PC", NoEnv));
        Assert.StartsWith("Pick a full folder path", ex.Message);
    }
}
