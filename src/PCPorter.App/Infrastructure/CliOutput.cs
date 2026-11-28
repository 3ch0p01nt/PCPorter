using System.IO;
using System.Text.Json;
using PCPorter.Core.Security;
using Serilog;

namespace PCPorter.App.Infrastructure;

/// <summary>How the scan, history and thumbs commands report a failure: one redacted line or one JSON object.</summary>
public static class CliOutput
{
    /// <summary>Prints <paramref name="message"/> (redacted) to stderr, or <c>{error, exitCode}</c> to stdout with --json.</summary>
    public static int Fail(bool json, string message, int code, TextWriter? stdout = null, TextWriter? stderr = null)
    {
        message = Redactor.Redact(message);
        if (json) (stdout ?? Console.Out).WriteLine(JsonSerializer.Serialize(new { error = message, exitCode = code }));
        else (stderr ?? Console.Error).WriteLine(message);
        return code;
    }

    /// <summary>
    /// A finished command's result: <c>{summary, folderWarnings, exitCode}</c> on stdout with --json, otherwise the text
    /// on stdout and each folder warning on stderr. Warnings are redacted.
    /// </summary>
    public static void Done(bool json, object summary, string text, IReadOnlyList<string> folderWarnings, int code,
        JsonSerializerOptions? options = null, TextWriter? stdout = null, TextWriter? stderr = null)
    {
        var warnings = folderWarnings.Select(Redactor.Redact).ToList();
        if (json) (stdout ?? Console.Out).WriteLine(JsonSerializer.Serialize(new { summary, folderWarnings = warnings, exitCode = code }, options));
        else
        {
            (stdout ?? Console.Out).WriteLine(text);
            foreach (var w in warnings) (stderr ?? Console.Error).WriteLine("Warning: " + w);
        }
    }

    /// <summary>The exit for an exception that ended a command (see <see cref="JobErrors"/>); failures are logged.</summary>
    public static int Fail(bool json, Exception ex, string command, TextWriter? stdout = null, TextWriter? stderr = null)
    {
        var err = JobErrors.Describe(ex, "the case", Logging.Folder);
        if (err.Kind == JobErrorKind.Failed) Log.Error(ex, "{Command} failed", command);
        var message = err.Kind switch
        {
            JobErrorKind.Cancelled => "Cancelled.",
            JobErrorKind.CantStart => err.Message,
            _ => $"{err.Title}: {err.Message}",
        };
        return Fail(json, message, err.ExitCode, stdout, stderr);
    }
}
