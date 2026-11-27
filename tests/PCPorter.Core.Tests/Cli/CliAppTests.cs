using PCPorter.Core.Cli;

namespace PCPorter.Core.Tests.Cli;

public class CliAppTests
{
    [Fact] public void Unknown_command_is_bad_args() =>
        Assert.Equal(ExitCodes.BadArguments, CliApp.Run(["frobnicate"], isElevated: true));

    [Fact] public void Backup_requires_elevation() =>
        Assert.Equal(ExitCodes.NotElevated, CliApp.Run(["backup", "--dest", @"E:\"], isElevated: false));

    [Fact] public void Backup_without_dest_is_bad_args() =>
        Assert.Equal(ExitCodes.BadArguments, CliApp.Run(["backup"], isElevated: true));

    [Fact] public void Backup_with_dest_elevated_is_ok() =>
        Assert.Equal(ExitCodes.Ok, CliApp.Run(["backup", "--dest", @"E:\", "--quiet"], isElevated: true));

    [Fact] public void Version_succeeds() =>
        Assert.Equal(ExitCodes.Ok, CliApp.Run(["--version"], isElevated: false));
}
