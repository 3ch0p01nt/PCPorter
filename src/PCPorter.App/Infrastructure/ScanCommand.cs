using System.CommandLine;
using System.IO;
using System.Text.Json;
using PCPorter.Collectors;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;
using PCPorter.Reports;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// <c>pcporter scan --out &lt;folder&gt; [--offline D:\] [--json] [--quiet] [--fail-on high|unusual] [--include-defender-prefs]</c>:
/// health &amp; security scan of this PC or of a dead PC's drive.
/// Exit codes: 0 ok, 1 partial, 2 failed, 3 bad arguments, 4 not elevated, 5 findings at the --fail-on level, 6 cancelled (Ctrl+C).
/// The app is a Windows (GUI) program: it attaches to the calling console, so in cmd use <c>start /wait pcporter scan ...</c>
/// (PowerShell waits by itself when you pipe it, e.g. <c>pcporter scan --out E:\ --json | Out-String</c>) to read the exit code.
/// </summary>
public static class ScanCommand
{
    sealed class ConsoleProgress(bool on) : IProgress<ScanProgress> { public void Report(ScanProgress v) { if (on) Console.Error.WriteLine(v.Message); } }

    public static Command Create(bool elevated)
    {
        var outOpt = new Option<DirectoryInfo>("--out") { Description = "Folder to write the case into (backup drive or a local folder)", Required = true };
        var offline = new Option<DirectoryInfo?>("--offline") { Description = "Scan another PC's Windows drive instead of this PC (for example D:\\)" };
        var json = new Option<bool>("--json") { Description = "Print a machine-readable summary on stdout" };
        var quiet = new Option<bool>("--quiet") { Description = "No progress lines on stderr" };
        var failOn = new Option<string?>("--fail-on") { Description = "Exit with code 5 when findings of this level exist: high (worth a look) or unusual (also unusual)" };
        failOn.AcceptOnlyFromAmong("high", "unusual");
        var defender = new Option<bool>("--include-defender-prefs") { Description = "Also record Microsoft Defender exclusions on work/school PCs" };
        var cmd = new Command("scan", "Check installed apps, antivirus, startup programs, security settings and PC health (read-only)") { outOpt, offline, json, quiet, failOn, defender };
        cmd.SetAction(parse =>
        {
            bool asJson = parse.GetValue(json);
            if (!elevated && parse.GetValue(offline) is null)
                return Fail(asJson, "Run PCPorter as administrator to scan this PC.", ExitCodes.NotElevated);

            using var cancel = new CliCancel();
            try
            {
                var r = ScanSetup.Run(parse.GetValue(outOpt)!.FullName,
                    new ScanJobOptions(parse.GetValue(offline)?.FullName, parse.GetValue(defender), elevated),
                    new ConsoleProgress(!asJson && !parse.GetValue(quiet)), cancel.Token);
                var f = ScanSetup.CountFindings(r);
                // Findings win over "partial": an offline scan is always partial (no running Windows to ask about
                // hardware), and --fail-on must still report what it found.
                bool flagged = parse.GetValue(failOn) is { } level && (f.WorthALook > 0 || level == "unusual" && f.Unusual > 0);
                int code = r.Run.Cancelled ? ExitCodes.Cancelled
                    : flagged ? ExitCodes.FindingsFound
                    : r.Run.AnyFailed || r.Run.AnyPartial ? ExitCodes.Partial : ExitCodes.Ok;
                var summary = new
                {
                    scanId = r.ScanId, casePath = r.CaseFolder, report = r.ReportPath, status = r.Run.Overall,
                    collectors = r.Run.Runs.Select(x => new { name = x.Collector, status = x.Status.ToString(), items = x.Items }),
                    findings = new { worthALook = f.WorthALook, unusual = f.Unusual },
                    warnings = r.Warnings.Count,
                };
                Console.WriteLine(asJson ? JsonSerializer.Serialize(new { summary, exitCode = code }) :
                    $"Report: {r.ReportPath ?? r.CaseFolder}\n{f.WorthALook} worth a look, {f.Unusual} unusual; " +
                    string.Join(", ", r.Run.Runs.Select(x => $"{x.Collector}: {x.Status} ({x.Items})")));
                Log.Information("scan {ScanId}: {Status}, exit {Code}", r.ScanId, summary.status, code);
                return code;
            }
            catch (Exception ex) { return CliOutput.Fail(asJson, ex, "scan"); }
        });
        return cmd;
    }

    static int Fail(bool json, string message, int code) => CliOutput.Fail(json, message, code);
}
