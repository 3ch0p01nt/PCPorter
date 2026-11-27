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
}
