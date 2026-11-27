using System.CommandLine;
using System.IO;
using System.Text.Json;
using PCPorter.Collectors.Sources;
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
            using var cts = new CancellationTokenSource();
            ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; cts.Cancel(); Console.Error.WriteLine("Stopping after the current step..."); };
            Console.CancelKeyPress += onCancel;
            try
            {
                var offlineRoot = parse.GetValue(offline)?.FullName;
                using ISystemSource source = offlineRoot is null ? new LiveSource() : new OfflineSource(offlineRoot);
                var notes = new List<string>();
                bool all = parse.GetValue(allUsers);
                if (all && source.IsLive && !elevated)
                {
                    notes.Add("PCPorter is not running as administrator, so only your own account was read. Run it as administrator to include the other accounts (ask them first).");
                    all = false;
                }
                var options = new HistoryJobOptions(all, !parse.GetValue(noRestore), notes);
                var r = HistoryJob.Run(parse.GetValue(outOpt)!.FullName, source, options, new ConsoleProgress(!json), ct: cts.Token);
                var s = HistoryJob.Summarize(r);
                var code = HistoryJob.ExitCode(r);
                Console.WriteLine(json ? JsonSerializer.Serialize(new { summary = s, exitCode = code }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }) :
                    $"Report: {s.Report}\n{s.Profiles} browser profiles: {s.Visits} visits, {s.Searches} searches, {s.Downloads} downloads, " +
                    $"{s.Bookmarks} bookmarks, {s.Tabs} tabs, {s.Forms} form entries; warnings {s.Warnings}");
                if (!json) foreach (var w in r.Scan.Warnings.Concat(r.FolderWarnings)) Console.Error.WriteLine("Warning: " + Redactor.Redact(w));
                Log.Information("history: {Profiles} profiles, {Visits} visits, {Warnings} warnings, exit {Code}", s.Profiles, s.Visits, s.Warnings, code);
                return code;
            }
            catch (OperationCanceledException) { return Fail(json, "Cancelled.", ExitCodes.Cancelled); }
            catch (CaseLocationRejectedException ex) { return Fail(json, ex.Message, ExitCodes.BadArguments); }
            catch (InvalidDataException ex) { return Fail(json, ex.Message, ExitCodes.BadArguments); }
            catch (InvalidOperationException ex) { return Fail(json, ex.Message, ExitCodes.BadArguments); }
            catch (UnauthorizedAccessException ex) { return Fail(json, "Access was denied: " + ex.Message, ExitCodes.Failed); }
            catch (IOException ex) { return Fail(json, "Could not write the case: " + ex.Message, ExitCodes.Failed); }
            catch (Exception ex)
            {
                Log.Error(ex, "history failed");
                return Fail(json, $"Something went wrong; details are in {Logging.Folder}.", ExitCodes.Failed);
            }
            finally { Console.CancelKeyPress -= onCancel; }
        });
        return cmd;
    }

    static int Fail(bool json, string message, int code)
    {
        message = Redactor.Redact(message);
        if (json) Console.WriteLine(JsonSerializer.Serialize(new { error = message, exitCode = code }));
        else Console.Error.WriteLine(message);
        return code;
    }
}
