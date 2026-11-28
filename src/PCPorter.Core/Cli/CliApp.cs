using System.CommandLine;

namespace PCPorter.Core.Cli;

/// <summary>Command-line entry point. The working commands (scan, history, thumbs, selftest) are added by the app.</summary>
public static class CliApp
{
    /// <param name="extraCommands">Commands implemented in higher layers (Forensics/Reports), added by the app.</param>
    public static int Run(string[] args, bool isElevated, params Command[] extraCommands)
    {
        var root = new RootCommand("PCPorter - move your PC and explore its history")
        {
            NotBuiltYet("backup", "Back up this PC"),
            NotBuiltYet("report", "Generate HTML reports from a backup"),
        };
        foreach (var extra in extraCommands) root.Subcommands.Add(extra);
        var parsed = root.Parse(args);
        if (parsed.Errors.Count > 0)
        {
            foreach (var error in parsed.Errors) Console.Error.WriteLine(error.Message);
            return ExitCodes.BadArguments;
        }
        return parsed.Invoke();
    }

    /// <summary>
    /// A planned command that does nothing yet. Hidden from the help, and if called anyway it says so and fails (exit 2)
    /// instead of pretending a backup was made. Any arguments are accepted, so old scripts get this message, not a parse error.
    /// </summary>
    static Command NotBuiltYet(string name, string description)
    {
        var cmd = new Command(name, description) { Hidden = true, TreatUnmatchedTokensAsErrors = false };
        cmd.SetAction(_ =>
        {
            Console.Error.WriteLine($"\"pcporter {name}\" is not built yet. Nothing was done.");
            return ExitCodes.Failed;
        });
        return cmd;
    }
}
