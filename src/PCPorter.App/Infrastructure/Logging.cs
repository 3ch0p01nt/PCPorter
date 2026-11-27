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
    public static string Folder { get; } = AppFolders.For("logs");

    public static void Init() => Log.Logger = new LoggerConfiguration()
        .MinimumLevel.Information()
        .WriteTo.File(new RedactingFormatter(), Path.Combine(Folder, "pcporter-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
        .CreateLogger();

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
