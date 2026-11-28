using PCPorter.App.Infrastructure;
using PCPorter.Core.Cli;
using PCPorter.Reports;

namespace PCPorter.App.Tests;

[Collection("Console")]
public class ThumbsCommandTests
{
    sealed class Stop : Exception;

    [Fact]
    public void All_users_without_administrator_reads_your_own_account_with_a_note()
    {
        GalleryJobFactory.Settings? seen = null;
        var output = ConsoleCapture.Run(() => CliApp.Run(["thumbs", "--out", Path.GetTempPath(), "--all-users"], false,
            ThumbsCommand.Create(false, (s, _) => { seen = s; throw new Stop(); })));
        Assert.False(seen!.AllUsers);
        Assert.Contains(HistorySetup.NotAdminNote, output.Err);
        Assert.NotEqual(ExitCodes.NotElevated, output.Code);
    }

    [Fact]
    public void All_users_as_administrator_is_passed_on()
    {
        GalleryJobFactory.Settings? seen = null;
        var output = ConsoleCapture.Run(() => CliApp.Run(["thumbs", "--out", Path.GetTempPath(), "--all-users"], true,
            ThumbsCommand.Create(true, (s, _) => { seen = s; throw new Stop(); })));
        Assert.True(seen!.AllUsers);
        Assert.DoesNotContain(HistorySetup.NotAdminNote, output.Err);
    }

    [Fact, Trait("Category", "Live")]   // reads this account's real thumbnail caches
    public void Json_is_wrapped_as_summary_and_exit_code_with_case_folder()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-thumbs-cli").FullName;
        try
        {
            // No live sources: the extra source list is empty and the resolver finds nothing; the job still writes a case.
            var output = ConsoleCapture.Run(() => CliApp.Run(["thumbs", "--out", root, "--json", "--no-web"], false,
                ThumbsCommand.Create(false, (_, _) => new ThumbnailJobOptions(ExtraSources: []))));
            using var doc = System.Text.Json.JsonDocument.Parse(output.Out);
            var code = doc.RootElement.GetProperty("exitCode").GetInt32();
            Assert.Equal(output.Code, code);
            var summary = doc.RootElement.GetProperty("summary");
            Assert.True(Directory.Exists(summary.GetProperty("caseFolder").GetString()));
            Assert.True(summary.TryGetProperty("report", out _));
        }
        finally { Directory.Delete(root, true); }
    }
}
