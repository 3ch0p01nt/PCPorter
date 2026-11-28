using PCPorter.App.Infrastructure;
using PCPorter.Core;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Core.Security;

namespace PCPorter.App.Tests;

public class JobErrorsTests
{
    [Fact]
    public void Only_refused_input_is_cant_start()
    {
        Assert.Equal(JobErrorKind.CantStart, JobErrors.Classify(new CaseLocationRejectedException("cloud folder")));
        Assert.Equal(JobErrorKind.CantStart, JobErrors.Classify(new SourceRejectedException("not a Windows drive")));
        // These used to be shown as "Can't start" / exit 3, as if the person had made a mistake.
        Assert.Equal(JobErrorKind.Failed, JobErrors.Classify(new InvalidOperationException("bug")));
        Assert.Equal(JobErrorKind.Failed, JobErrors.Classify(new InvalidDataException("corrupt hive")));
        Assert.Equal(JobErrorKind.Failed, JobErrors.Classify(new NullReferenceException()));
        Assert.Equal(JobErrorKind.Failed, JobErrors.Classify(new IOException("disk full")));
        Assert.Equal(JobErrorKind.Failed, JobErrors.Classify(new UnsafeAppFolderException("unsafe")));
        Assert.Equal(JobErrorKind.Cancelled, JobErrors.Classify(new OperationCanceledException()));
        Assert.Equal(JobErrorKind.Cancelled, JobErrors.Classify(new TaskCanceledException()));
    }

    [Fact]
    public void Exit_codes()
    {
        Assert.Equal(ExitCodes.BadArguments, JobErrors.Describe(new SourceRejectedException("x"), "the report", "L").ExitCode);
        Assert.Equal(ExitCodes.Failed, JobErrors.Describe(new InvalidOperationException("x"), "the report", "L").ExitCode);
        Assert.Equal(ExitCodes.Failed, JobErrors.Describe(new UnauthorizedAccessException("x"), "the report", "L").ExitCode);
        Assert.Equal(ExitCodes.Cancelled, JobErrors.Describe(new OperationCanceledException(), "the report", "L").ExitCode);
    }

    [Fact]
    public void Messages_are_redacted_and_failures_point_at_the_log()
    {
        var e = JobErrors.Describe(new InvalidOperationException("login failed for password=Hunter2Secret"), "the report", @"C:\logs");
        Assert.DoesNotContain("Hunter2Secret", e.Message);
        Assert.Contains(@"C:\logs", e.Message);
        Assert.Equal("Something went wrong", e.Title);

        var io = JobErrors.Describe(new IOException("password=Hunter2Secret"), "the report", "L");
        Assert.Equal("Couldn't save the report", io.Title);
        Assert.DoesNotContain("Hunter2Secret", io.Message);

        var start = JobErrors.Describe(new CaseLocationRejectedException("password=Hunter2Secret"), "the report", "L");
        Assert.Equal("Can't start", start.Title);
        Assert.DoesNotContain("Hunter2Secret", start.Message);
    }
}
