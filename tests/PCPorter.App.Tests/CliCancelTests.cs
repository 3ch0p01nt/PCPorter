using PCPorter.App.Infrastructure;
using PCPorter.Core.Cli;

namespace PCPorter.App.Tests;

public class CliCancelTests
{
    [Fact]
    public void First_press_cancels_the_job_and_keeps_the_process()
    {
        var exits = new List<int>();
        using var c = new CliCancel(exits.Add, TextWriter.Null, hookConsole: false);
        Assert.True(c.Press());
        Assert.True(c.Token.IsCancellationRequested);
        Assert.Empty(exits);
    }

    [Fact]
    public void Second_press_ends_the_process_with_exit_6()
    {
        var exits = new List<int>();
        using var c = new CliCancel(exits.Add, TextWriter.Null, hookConsole: false);
        c.Press();
        c.Press();
        Assert.Equal([ExitCodes.Cancelled], exits);
    }
}
