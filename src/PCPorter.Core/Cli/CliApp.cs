using System.CommandLine;

namespace PCPorter.Core.Cli;

/// <summary>Command-line entry point. Commands are wired to real engines in later phases.</summary>
public static class CliApp
{
    /// <param name="extraCommands">Commands implemented in higher layers (Forensics/Reports), added by the app.</param>
    public static int Run(string[] args, bool isElevated, params Command[] extraCommands)
    {
        var dest = new Option<DirectoryInfo>("--dest") { Description = "Backup destination folder", Required = true };
        var from = new Option<DirectoryInfo>("--from") { Description = "Existing backup or case folder", Required = true };
        var quiet = new Option<bool>("--quiet") { Description = "No prompts; log only" };

        var backup = new Command("backup", "Back up this PC") { dest, quiet };
        backup.SetAction(_ => isElevated ? ExitCodes.Ok : ExitCodes.NotElevated);   // Phase 5 wires the backup engine

        var report = new Command("report", "Generate HTML reports from a backup") { from, quiet };
        report.SetAction(_ => ExitCodes.Ok);                                          // Phase 3 wires the report engine

        var root = new RootCommand("PCPorter - move your PC and explore its history") { backup, report };
        foreach (var extra in extraCommands) root.Subcommands.Add(extra);
        var parsed = root.Parse(args);
        if (parsed.Errors.Count > 0)
        {
            foreach (var error in parsed.Errors) Console.Error.WriteLine(error.Message);
            return ExitCodes.BadArguments;
        }
        return parsed.Invoke();
    }
}
