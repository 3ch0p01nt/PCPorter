using PCPorter.App.Infrastructure;
using static PCPorter.App.Infrastructure.ConsoleAttach;

namespace PCPorter.App.Tests;

public class ConsoleAttachTests
{
    [Theory]
    [InlineData(false, false, Plan.Attach)]
    [InlineData(false, true, Plan.Attach)]           // stderr to a file: attaching only fills the missing stdout
    [InlineData(true, false, Plan.AttachForStderr)]  // "--json > out.json": progress and errors still reach the console
    [InlineData(true, true, Plan.None)]
    public void Attaches_for_every_stream_that_is_not_redirected(bool stdout, bool stderr, Plan expected) =>
        Assert.Equal(expected, ConsoleAttach.Decide(stdout, stderr));
}
