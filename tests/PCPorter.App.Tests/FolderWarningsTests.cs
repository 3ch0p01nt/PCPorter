using System.Text.Json;
using PCPorter.App.Infrastructure;
using PCPorter.Collectors;
using PCPorter.Reports;

namespace PCPorter.App.Tests;

public class FolderWarningsTests
{
    // The text CaseFolder.Create writes for a drive without file permissions.
    const string ExFat = "This drive uses exFAT, which cannot restrict who can read the files. Anyone with the drive can open the case. Consider BitLocker To Go.";

    [Fact]
    public void Scan_folder_warnings_are_picked_out_of_the_scan_warnings()
    {
        var run = new ScanRunResult([]);
        var r = new ScanJobResult(@"E:\PCPorter\X_20261127T140501Z_a1b2c3", "id", run, [ExFat, "Defender could not be asked"], [], null, "a.json", "X", false);
        Assert.Equal([ExFat], FolderWarnings.Of(r));
    }

    [Fact]
    public void Result_bar_text_lists_each_warning()
    {
        Assert.Equal("Done.", FolderWarnings.Append("Done.", []));
        Assert.Equal("Done.\n\nNote: " + ExFat, FolderWarnings.Append("Done.", [ExFat]));
    }

    [Fact]
    public void Json_carries_folder_warnings_next_to_the_summary()
    {
        using var o = new StringWriter();
        CliOutput.Done(true, new { caseFolder = "C" }, "text", [ExFat], 1, stdout: o, stderr: TextWriter.Null);
        using var doc = JsonDocument.Parse(o.ToString());
        Assert.Equal("C", doc.RootElement.GetProperty("summary").GetProperty("caseFolder").GetString());
        Assert.Equal(ExFat, doc.RootElement.GetProperty("folderWarnings")[0].GetString());
        Assert.Equal(1, doc.RootElement.GetProperty("exitCode").GetInt32());
    }

    [Fact]
    public void Text_mode_prints_folder_warnings_on_stderr()
    {
        using var o = new StringWriter();
        using var e = new StringWriter();
        CliOutput.Done(false, new { }, "Report: x", [ExFat], 0, stdout: o, stderr: e);
        Assert.Equal("Report: x", o.ToString().Trim());
        Assert.Equal("Warning: " + ExFat, e.ToString().Trim());
    }
}
