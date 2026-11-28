using System.IO;
using PCPorter.Core;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;
using PCPorter.Reports;

namespace PCPorter.App.Infrastructure;

public enum JobErrorKind
{
    /// <summary>The person's input was refused (save folder, drive): "Can't start", exit 3, nothing remembered.</summary>
    CantStart,
    /// <summary>Stopped by the person: exit 6.</summary>
    Cancelled,
    /// <summary>Anything else is a program or system failure: logged, remembered as Failed, exit 2.</summary>
    Failed,
}

/// <summary>What the page shows and the command prints for an exception that ended a job.</summary>
/// <param name="Message">Already passed through <see cref="Redactor.Redact"/>.</param>
public sealed record JobError(JobErrorKind Kind, string Title, string Message)
{
    public int ExitCode => Kind switch
    {
        JobErrorKind.CantStart => ExitCodes.BadArguments,
        JobErrorKind.Cancelled => ExitCodes.Cancelled,
        _ => ExitCodes.Failed,
    };
}

/// <summary>
/// One mapping for all three pages and all three commands. Only the two "your input was refused" exceptions are
/// "Can't start"; an unexpected InvalidOperationException is a bug and must not be shown as the person's mistake.
/// </summary>
public static class JobErrors
{
    public static JobErrorKind Classify(Exception ex) => ex switch
    {
        // A scan that failed after creating its case folder wraps the real error.
        ScanJobFailedException { InnerException: { } inner } => Classify(inner),
        OperationCanceledException => JobErrorKind.Cancelled,
        CaseLocationRejectedException or SourceRejectedException => JobErrorKind.CantStart,
        _ => JobErrorKind.Failed,
    };

    /// <summary>A full drive: Windows' disk-full errors, or the case database's SQLITE_FULL (13), which is not an IOException.</summary>
    static bool IsDiskFull(Exception e) =>
        e is Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 13 }
        || (e is IOException && (e.HResult & 0xFFFF) is 0x70 /* ERROR_DISK_FULL */ or 0x27 /* ERROR_HANDLE_DISK_FULL */);

    /// <param name="what">The job's result in a few words, for example "the report" or "the results".</param>
    /// <param name="logFolder">Where the details are logged.</param>
    public static JobError Describe(Exception ex, string what, string logFolder)
    {
        var kind = Classify(ex);
        var kept = (ex as ScanJobFailedException)?.CaseFolderPath;
        var cause = ex is ScanJobFailedException { InnerException: { } inner } ? inner : ex;
        var message = Redactor.Redact(cause.Message)
            + (kept is null ? "" : $" What was saved before the problem is in {kept}.");
        return kind switch
        {
            JobErrorKind.Cancelled => new(kind, "Stopped", "Stopped before the end. Nothing on the PC was changed."),
            JobErrorKind.CantStart => new(kind, "Can't start", message),
            _ => cause switch
            {
                _ when IsDiskFull(cause) => new(kind, $"Couldn't save {what}", "There is not enough free space on the drive. " +
                    "Free up some space or pick another drive, then try again." + (kept is null ? "" : $" What was saved before the problem is in {kept}.")),
                UnsafeAppFolderException => new(kind, "PCPorter's working folder is not safe", message),
                IOException or UnauthorizedAccessException => new(kind, $"Couldn't save {what}", message),
                _ => new(kind, "Something went wrong", $"{message} Details are in the log folder: {logFolder}"),
            },
        };
    }
}
