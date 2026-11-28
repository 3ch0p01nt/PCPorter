using PCPorter.Core.Cli;

namespace PCPorter.Core.Tests.Cli;

public class CliAppTests
{
    [Fact] public void Unknown_command_is_bad_args() =>
        Assert.Equal(ExitCodes.BadArguments, CliApp.Run(["frobnicate"], isElevated: true));

    // backup and report are not built: they must never report success (exit 0) for work that was not done.
    [Theory]
    [InlineData("backup", "--dest", @"E:\", "--quiet")]
    [InlineData("backup")]
    [InlineData("report", "--from", @"E:\PCPorter")]
    public void Unbuilt_commands_fail_with_exit_2(params string[] args)
    {
        Assert.Equal(ExitCodes.Failed, CliApp.Run(args, isElevated: true));
        Assert.Equal(ExitCodes.Failed, CliApp.Run(args, isElevated: false));
    }

    [Fact]
    public void Unbuilt_commands_are_hidden_from_help()
    {
        var old = Console.Out;
        using var o = new StringWriter();
        Console.SetOut(o);
        try { CliApp.Run(["--help"], isElevated: false); }
        finally { Console.SetOut(old); }
        Assert.Contains("--version", o.ToString());                 // the help really was captured
        Assert.DoesNotContain("backup", o.ToString());
        Assert.DoesNotContain("report", o.ToString());
    }

    [Fact] public void Version_succeeds() =>
        Assert.Equal(ExitCodes.Ok, CliApp.Run(["--version"], isElevated: false));
}
