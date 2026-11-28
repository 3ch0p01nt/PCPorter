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

    /// <summary>
    /// One log entry: the redacted message on ONE line (line breaks and other control characters in it are written as
    /// escapes such as \n, so text from the old PC cannot forge extra log lines), then the redacted exception, if any,
    /// with its own line breaks kept and any other control characters escaped.
    /// </summary>
    public sealed class RedactingFormatter : ITextFormatter
    {
        readonly MessageTemplateTextFormatter _line = new("{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}");
        readonly MessageTemplateTextFormatter _exception = new("{Exception}");

        public void Format(LogEvent logEvent, TextWriter output)
        {
            output.Write(Escape(Render(_line, logEvent), keepLineBreaks: false));
            output.Write(Environment.NewLine);
            if (logEvent.Exception is not null) output.Write(Escape(Render(_exception, logEvent), keepLineBreaks: true));
        }

        static string Render(MessageTemplateTextFormatter formatter, LogEvent logEvent)
        {
            using var sw = new StringWriter();
            formatter.Format(logEvent, sw);
            return Redactor.Redact(sw.ToString());
        }

        static string Escape(string text, bool keepLineBreaks)
        {
            if (!text.Any(NeedsEscape)) return text;
            var sb = new System.Text.StringBuilder(text.Length + 16);
            foreach (var c in text)
            {
                if (!NeedsEscape(c) || (keepLineBreaks && c is '\r' or '\n')) sb.Append(c);
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\t') sb.Append("\\t");
                else sb.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        /// <summary>Control characters (C0, DEL, C1 incl. NEL) and the Unicode line and paragraph separators.</summary>
        static bool NeedsEscape(char c) => char.IsControl(c) || c == (char)0x2028 || c == (char)0x2029;
    }
}
