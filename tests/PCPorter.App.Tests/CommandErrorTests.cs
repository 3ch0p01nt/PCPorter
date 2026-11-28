using PCPorter.App.Infrastructure;
using PCPorter.Core;
using PCPorter.Core.Cli;

namespace PCPorter.App.Tests;

[Collection("Console")]
public class CommandErrorTests
{
    static int Thumbs(Exception thrown) =>
        CliApp.Run(["thumbs", "--out", Path.GetTempPath(), "--json"], false,
            ThumbsCommand.Create(false, (_, _) => throw thrown));

    [Fact] public void A_program_failure_is_exit_2_not_bad_arguments() =>
        Assert.Equal(ExitCodes.Failed, Thumbs(new InvalidOperationException("bug")));

    [Fact] public void Refused_input_is_exit_3() =>
        Assert.Equal(ExitCodes.BadArguments, Thumbs(new SourceRejectedException("not a Windows drive")));

    [Fact] public void Cancelled_is_exit_6() =>
        Assert.Equal(ExitCodes.Cancelled, Thumbs(new OperationCanceledException()));

    [Fact]
    public void Json_failure_is_one_redacted_object()
    {
        var output = ConsoleCapture.Run(() => Thumbs(new InvalidOperationException("password=Hunter2Secret")));
        Assert.Equal(ExitCodes.Failed, output.Code);
        Assert.DoesNotContain("Hunter2Secret", output.Out);
        using var doc = System.Text.Json.JsonDocument.Parse(output.Out);
        Assert.Equal(ExitCodes.Failed, doc.RootElement.GetProperty("exitCode").GetInt32());
    }
}

/// <summary>Swaps Console.Out/Error for one call. Tests that use it share the "Console" collection, so never run in parallel.</summary>
static class ConsoleCapture
{
    public sealed record Result(int Code, string Out, string Err);

    public static Result Run(Func<int> action)
    {
        var (oldOut, oldErr) = (Console.Out, Console.Error);
        using var o = new StringWriter();
        using var e = new StringWriter();
        Console.SetOut(o); Console.SetError(e);
        try { var code = action(); return new(code, o.ToString(), e.ToString()); }
        finally { Console.SetOut(oldOut); Console.SetError(oldErr); }
    }
}

[CollectionDefinition("Console", DisableParallelization = true)]
public sealed class ConsoleCollection;
