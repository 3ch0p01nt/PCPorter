using System.CommandLine;
using System.IO;
using System.Text.Json;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Forensics.Gallery;
using PCPorter.Reports;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// <c>pcporter thumbs --out &lt;folder&gt; [--all-users] [--no-web] [--full-index] [--json]</c>: build the "images viewed" gallery.
/// Exit codes: 0 ok, 1 partial (something could not be read), 2 failed, 3 bad arguments, 6 cancelled (Ctrl+C).
/// Not being administrator is never exit 4: --all-users then reads your own account with a note, like history.
/// </summary>
public static class ThumbsCommand
{
    /// <summary>Synchronous progress: WPF's Progress&lt;T&gt; posts to the dispatcher, which is blocked during a CLI run.</summary>
    sealed class ConsoleProgress(bool enabled) : IProgress<string>
    {
        public void Report(string value) { if (enabled) Console.Error.WriteLine(value); }
    }

    public static Command Create(bool elevated, Func<GalleryJobFactory.Settings, IProgress<string>, ThumbnailJobOptions> setup)
    {
        var outOpt = new Option<DirectoryInfo>("--out") { Description = "Folder to write the case into (backup drive or a local folder - not a cloud-synced folder)", Required = true };
        var allUsers = new Option<bool>("--all-users") { Description = "Also read every other account on this PC (needs administrator rights and their consent)" };
        var noWeb = new Option<bool>("--no-web") { Description = "Skip web browser caches" };
        var fullIndex = new Option<bool>("--full-index") { Description = "Copy the search index so its most recent changes are included (slower, needs free space)" };
        var jsonOpt = new Option<bool>("--json") { Description = "Print a machine-readable summary on stdout" };
        var cmd = new Command("thumbs", "Build a gallery of images viewed on this PC (thumbnails, web caches, screenshots, opened files)") { outOpt, allUsers, noWeb, fullIndex, jsonOpt };
        cmd.SetAction(parse =>
        {
            var json = parse.GetValue(jsonOpt);
            using var cancel = new CliCancel();
            try
            {
                // Like history: "all accounts" without administrator rights reads your own account, with a note.
                var notAdmin = parse.GetValue(allUsers) && !elevated;
                if (notAdmin && !json) Console.Error.WriteLine("Note: " + HistorySetup.NotAdminNote);
                var settings = new GalleryJobFactory.Settings(parse.GetValue(allUsers) && elevated, !parse.GetValue(noWeb), parse.GetValue(fullIndex));
                var progress = new ConsoleProgress(!json);
                var options = setup(settings, progress);
                if (notAdmin) options = options with { ExtraNotes = [.. options.ExtraNotes ?? [], HistorySetup.NotAdminNote] };
                var r = ThumbnailJob.Run(parse.GetValue(outOpt)!.FullName, progress: progress, options: options, ct: cancel.Token);
                var items = r.Scan.Items;
                var s = r.Scan.Summary;   // original-file counts are for thumbnails only (restore-point copies merged)
                var summary = new
                {
                    report = r.ReportPath, caseFolder = r.CaseFolder,
                    thumbnails = s.Thumbnails,
                    withoutPicture = s.WithoutPicture,
                    deletedOriginals = s.DeletedOriginals,
                    folderGone = s.FolderGone,
                    unreachable = s.Unreachable,
                    onlyInRestorePoints = s.OnlyInRestorePoints,
                    web = s.Web, screenshots = s.Screenshots, opened = s.Opened, icons = s.Icons,
                    warnings = r.Scan.Warnings.Count + r.FolderWarnings.Count,
                };
                var code = summary.warnings > 0 ? ExitCodes.Partial : ExitCodes.Ok;
                CliOutput.Done(json, summary,
                    $"Report: {r.ReportPath}\nThumbnails {summary.thumbnails}, web {summary.web}, screenshots {summary.screenshots}, opened {summary.opened}; " +
                    $"deleted originals {summary.deletedOriginals}, no picture kept {summary.withoutPicture}; warnings {summary.warnings}",
                    r.FolderWarnings, code);
                Log.Information("thumbs: {Count} items, {Warnings} warnings, exit {Code}", items.Count, summary.warnings, code);
                return code;
            }
            catch (Exception ex) { return CliOutput.Fail(json, ex, "thumbs"); }
        });
        return cmd;
    }
}
