using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class StartupCheckTests
{
    const string Temp = @"C:\Users\Pat\AppData\Local\Temp\";
    const string Extracted = @"D:\PCPorter\";

    static Func<string, bool> Files(string dir, params string[] names)
    {
        var set = new HashSet<string>(names.Select(n => Path.Combine(dir, n)), StringComparer.OrdinalIgnoreCase);
        return set.Contains;
    }

    static string[] AllNative => [.. StartupCheck.NativeFiles];

    [Fact]
    public void Extracted_folder_with_every_dll_starts()
        => Assert.Null(StartupCheck.Problem(Extracted, Temp, Files(Extracted, AllNative)));

    [Fact]
    public void Dev_build_is_never_checked_even_in_temp()
    {
        var dir = Temp + @"Temp1_PCPorter.zip\PCPorter\";
        Assert.Null(StartupCheck.Problem(dir, Temp, Files(dir, StartupCheck.EntryAssemblyFile)));
    }

    [Fact]
    public void Quarantined_dll_is_named()
    {
        var present = AllNative.Where(n => n != "wpfgfx_cor3.dll").ToArray();
        var problem = StartupCheck.Problem(Extracted, Temp, Files(Extracted, present));
        Assert.NotNull(problem);
        Assert.StartsWith("PCPorter can't start from here. Right-click the zip, choose Extract All", problem);
        Assert.EndsWith("your antivirus may have removed one of its files: wpfgfx_cor3.dll.", problem);
    }

    [Fact]
    public void Exe_copied_alone_from_zip_view_is_stopped()
    {
        var dir = Temp + @"Temp1_PCPorter-1.2.zip\PCPorter\";
        var problem = StartupCheck.Problem(dir, Temp, Files(dir));
        Assert.NotNull(problem);
        Assert.Contains("D3DCompiler_47_cor3.dll", problem);
    }

    [Fact]
    public void Zip_view_is_stopped_even_with_the_dlls_present()
    {
        var dir = Temp + @"Temp3_pcporter.ZIP\";
        var problem = StartupCheck.Problem(dir, Temp, Files(dir, AllNative));
        Assert.Equal(StartupCheck.Message(null), problem);
        Assert.DoesNotContain("antivirus", problem);
    }

    [Theory]
    [InlineData(@"C:\Users\Pat\AppData\Local\Temp\Temp1_PCPorter.zip\PCPorter", true)]
    [InlineData(@"C:\Users\Pat\AppData\Local\Temp\Temp12_x.zip", true)]
    [InlineData(@"C:\Users\Pat\AppData\Local\Temp\PCPorter", false)]           // extracted into temp by hand: fine
    [InlineData(@"C:\Users\Pat\AppData\Local\Temp\Temp1_PCPorter\x", false)]    // no .zip in the name
    [InlineData(@"D:\Temp1_PCPorter.zip\PCPorter", false)]                     // not under the temp folder
    public void Zip_view_folder_rule(string dir, bool expected)
        => Assert.Equal(expected, StartupCheck.IsInsideZipView(dir, Temp));
}
