using System.CommandLine;
using System.IO;
using System.Text.Json;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;
using PCPorter.Reports;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// <c>pcporter history --out &lt;folder&gt; [--all-users] [--offline D:\] [--no-restore-points] [--json]</c>: web history report.
/// Exit codes: 0 ok, 1 partial (something was skipped), 2 failed, 3 bad arguments, 6 cancelled (Ctrl+C).
/// Not being administrator is never exit 4: "all accounts" then falls back to your own account with a note.
/// </summary>
public static class HistoryCommand
{
    /// <summary>Synchronous progress: WPF's Progress&lt;T&gt; posts to the dispatcher, which is blocked during a CLI run.</summary>
    sealed class ConsoleProgress(bool enabled) : IProgress<string>
    {
        public void Report(string value) { if (enabled) Console.Error.WriteLine(value); }
    }

    public static Command Create(bool elevated)
    {
        var outOpt = new Option<DirectoryInfo>("--out") { Description = "Folder to write the case into (backup drive or a local folder - not a cloud-synced folder)", Required = true };
        var allUsers = new Option<bool>("--all-users") { Description = "Also read every other account on this PC (needs administrator rights and their consent)" };
        var offline = new Option<DirectoryInfo?>("--offline") { Description = "Read another PC's Windows drive instead of this PC (for example D:\\); shows every account" };
        var noRestore = new Option<bool>("--no-restore-points") { Description = "Do not look in existing restore points" };
        var jsonOpt = new Option<bool>("--json") { Description = "Print a machine-readable summary on stdout" };
        var cmd = new Command("history", "Build a report of web browsing history (visits, searches, downloads, bookmarks, tabs, form entries) - read-only") { outOpt, allUsers, offline, noRestore, jsonOpt };
        cmd.SetAction(parse =>
        {
            var json = parse.GetValue(jsonOpt);
            using var cancel = new CliCancel();
            try
            {
                var request = new HistoryRequest(parse.GetValue(outOpt)!.FullName, parse.GetValue(offline)?.FullName,
                    parse.GetValue(allUsers), !parse.GetValue(noRestore));
                var r = HistorySetup.Run(request, elevated, new ConsoleProgress(!json), ct: cancel.Token);
                var s = HistoryJob.Summarize(r);
                var code = HistoryJob.ExitCode(r);
                Console.WriteLine(json ? JsonSerializer.Serialize(new { summary = s, exitCode = code }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }) :
                    $"Report: {s.Report}\n{s.Profiles} browser profiles: {s.Visits} visits, {s.Searches} searches, {s.Downloads} downloads, " +
                    $"{s.Bookmarks} bookmarks, {s.Tabs} tabs, {s.Forms} form entries; warnings {s.Warnings}");
                if (!json) foreach (var w in r.Scan.Warnings.Concat(r.FolderWarnings)) Console.Error.WriteLine("Warning: " + Redactor.Redact(w));
                Log.Information("history: {Profiles} profiles, {Visits} visits, {Warnings} warnings, exit {Code}", s.Profiles, s.Visits, s.Warnings, code);
                return code;
            }
            catch (Exception ex) { return CliOutput.Fail(json, ex, "history"); }
        });
        return cmd;
    }
}
