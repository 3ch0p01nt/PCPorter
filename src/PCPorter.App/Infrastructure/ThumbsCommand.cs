using System.CommandLine;
using System.IO;
using System.Text.Json;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Forensics.Gallery;
using PCPorter.Reports;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary><c>pcporter thumbs --out &lt;folder&gt; [--all-users] [--no-web] [--json]</c>: build the "images viewed" gallery.</summary>
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
            try
            {
                var settings = new GalleryJobFactory.Settings(parse.GetValue(allUsers), !parse.GetValue(noWeb), parse.GetValue(fullIndex));
                var progress = new ConsoleProgress(!json);
                var r = ThumbnailJob.Run(parse.GetValue(outOpt)!.FullName, progress: progress, options: setup(settings, progress));
                var items = r.Scan.Items;
                var summary = new
                {
                    report = r.ReportPath, caseFolder = r.CaseFolder,
                    thumbnails = items.Count(i => i.Kind == "thumbnail"),
                    withoutPicture = items.Count(i => !i.HasImage),
                    deletedOriginals = items.Count(i => i.Status == OriginalStatus.Deleted),
                    unreachable = items.Count(i => i.Status == OriginalStatus.Unreachable),
                    web = items.Count(i => i.Kind == "web"), screenshots = items.Count(i => i.Kind == "screenshot"),
                    opened = items.Count(i => i.Kind == "opened"), icons = items.Count(i => i.Kind == "icon"),
                    warnings = r.Scan.Warnings.Count + r.FolderWarnings.Count,
                };
                Console.WriteLine(json ? JsonSerializer.Serialize(summary) :
                    $"Report: {r.ReportPath}\nThumbnails {summary.thumbnails}, web {summary.web}, screenshots {summary.screenshots}, opened {summary.opened}; " +
                    $"deleted originals {summary.deletedOriginals}, no picture kept {summary.withoutPicture}; warnings {summary.warnings}");
                foreach (var w in r.FolderWarnings) Console.Error.WriteLine("Warning: " + w);
                Log.Information("thumbs: {Count} items, {Warnings} warnings", items.Count, summary.warnings);
                return summary.warnings > 0 ? ExitCodes.Partial : ExitCodes.Ok;
            }
            catch (Exception ex) { return CliOutput.Fail(json, ex, "thumbs"); }
        });
        return cmd;
    }
}
