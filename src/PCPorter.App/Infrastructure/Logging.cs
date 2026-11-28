using System.IO;
using PCPorter.Core.Security;
using Serilog;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// Rolling daily log files, kept for 14 days: %ProgramData%\PCPorter\logs (admin-only) when elevated, else
/// %LocalAppData%\PCPorter\logs. Every line, including exception text, passes through the redactor first.
/// </summary>
public static class Logging
{
    /// <summary>The log folder, known after <see cref="Init"/> (empty before).</summary>
    public static string Folder { get; private set; } = "";

    /// <summary>Opens the log. Elevated, the admin-only folder must be safe, or PCPorter does not start.</summary>
    /// <exception cref="UnsafeAppFolderException">Elevated, and %ProgramData%\PCPorter could not be made admin-only.</exception>
    /// <exception cref="IOException">The log folder could not be created.</exception>
    /// <exception cref="UnauthorizedAccessException">The log folder could not be created.</exception>
    public static void Init()
    {
        Folder = AppFolders.For("logs");
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(new RedactingFormatter(), Path.Combine(Folder, "pcporter-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
            .CreateLogger();
    }

    /// <summary>What to tell the person when <see cref="Init"/> failed (the program then exits with code 2).</summary>
    public static string StartFailure(Exception ex) => ex is UnsafeAppFolderException
        ? "PCPorter can't start: " + Redactor.Redact(ex.Message)
        : "PCPorter can't start: its log folder could not be created (" + Redactor.Redact(ex.Message) + ")";

    public static void Close() => Log.CloseAndFlush();

    sealed class RedactingFormatter : ITextFormatter
    {
        readonly MessageTemplateTextFormatter _inner = new("{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}");

        public void Format(LogEvent logEvent, TextWriter output)
        {
            using var sw = new StringWriter();
            _inner.Format(logEvent, sw);
            output.Write(Redactor.Redact(sw.ToString()));
        }
    }
}
