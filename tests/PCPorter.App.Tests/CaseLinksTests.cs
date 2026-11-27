using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class CaseLinksTests
{
    const string Case = @"E:\Backups\PCPorter\MY-PC_20261127T140501Z_a1b2c3";

    [Theory]
    [InlineData(Case + @"\HealthReport.html")]
    [InlineData(Case + @"\History.html")]
    [InlineData(Case + @"\gallery\Thumbnails.html")]
    [InlineData(@"E:\PCPorter\OldPC_20261127T140501Z_000fff\report.HTML")]
    public void Html_inside_a_case_folder_is_a_report(string path) => Assert.True(CaseLinks.LooksLikeReport(path));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(Case + @"\run.exe")]                                       // not html
    [InlineData(Case + @"\report.html.lnk")]
    [InlineData(Case + @"\report.hta")]
    [InlineData(@"E:\Backups\PCPorter\report.html")]                       // not inside a case folder
    [InlineData(@"E:\Backups\MY-PC_20261127T140501Z_a1b2c3\report.html")]   // parent is not "PCPorter"
    [InlineData(@"E:\Backups\PCPorter\MY-PC_20261127T1405Z_a1b2c3\report.html")]   // wrong time format
    [InlineData(@"E:\Backups\PCPorter\MY-PC_20261127T140501Z_A1B2C3\report.html")] // PCPorter writes lowercase hex
    [InlineData(Case + @"\..\..\evil.html")]                                // relative parts
    [InlineData(@"\\server\share\PCPorter\MY-PC_20261127T140501Z_a1b2c3\report.html")]   // network share
    [InlineData(@"\\?\E:\Backups\PCPorter\MY-PC_20261127T140501Z_a1b2c3\report.html")]   // device path
    [InlineData(@"E:/Backups/PCPorter/MY-PC_20261127T140501Z_a1b2c3/report.html")]       // not normal form
    [InlineData(@"report.html")]                                            // relative
    [InlineData(Case + @"\")]                                               // a folder
    public void Anything_else_is_not_a_report(string? path) => Assert.False(CaseLinks.LooksLikeReport(path));

    [Fact]
    public void Case_folder_shape()
    {
        Assert.True(CaseLinks.LooksLikeCaseFolder(Case));
        Assert.True(CaseLinks.LooksLikeCaseFolder(Case + @"\"));
        Assert.False(CaseLinks.LooksLikeCaseFolder(@"E:\Backups\PCPorter"));
        Assert.False(CaseLinks.LooksLikeCaseFolder(Case + @"\gallery"));
        Assert.False(CaseLinks.LooksLikeCaseFolder(@"C:\Windows\System32"));
        Assert.False(CaseLinks.LooksLikeCaseFolder(@"\\server\PCPorter\MY-PC_20261127T140501Z_a1b2c3"));
    }

    [Fact]
    public void A_remembered_report_must_also_exist()
    {
        Assert.False(CaseLinks.IsReport(Case + @"\HealthReport.html", _ => false));
        Assert.True(CaseLinks.IsReport(Case + @"\HealthReport.html", _ => true));
        Assert.False(CaseLinks.IsReport(@"C:\Users\me\evil.html", _ => true));
        Assert.False(CaseLinks.IsCaseFolder(Case, _ => false));
        Assert.True(CaseLinks.IsCaseFolder(Case, _ => true));
    }

    [Fact]
    public void A_remembered_run_from_settings_json_passes_the_same_check()
    {
        var good = new PCPorter.Core.Config.LastRun(DateTime.Now, PCPorter.Core.Config.RunOutcome.Ok, "x", Case + @"\HealthReport.html", Case);
        Assert.Equal(good, Remembered.Recall(good, _ => true, _ => true));
        Assert.Null(Remembered.Recall(good with { ReportPath = @"C:\Windows\System32\cmd.exe" }, _ => true, _ => true));
        Assert.Null(Remembered.Recall(good with { ReportPath = @"C:\Users\me\Downloads\evil.html" }, _ => true, _ => true));
        Assert.Null(Remembered.Recall(good, _ => false, _ => true));                       // report gone
        Assert.Null(Remembered.Recall(good with { CaseFolder = @"C:\Windows" }, _ => true, _ => true)!.CaseFolder);
        Assert.Null(Remembered.Recall(null));
    }

    [Fact]
    public void Opens_through_windows_own_explorer_by_full_path_without_shell_execute()
    {
        var psi = CaseLinks.Explorer(Case + @"\My Report.html");
        Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), psi.FileName);
        Assert.True(Path.IsPathFullyQualified(psi.FileName));
        Assert.False(psi.UseShellExecute);
        Assert.Equal([Case + @"\My Report.html"], psi.ArgumentList);
    }
}
