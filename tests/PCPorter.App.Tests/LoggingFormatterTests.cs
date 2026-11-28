using PCPorter.App.Infrastructure;
using Serilog.Events;
using Serilog.Parsing;

namespace PCPorter.App.Tests;

/// <summary>Text from the old PC (a value, a file name) logged as a message property must not forge log lines.</summary>
public class LoggingFormatterTests
{
    // Built from char codes: NEL, LINE SEPARATOR, BEL, SOH.
    static readonly string Nel = ((char)0x85).ToString(), LineSep = ((char)0x2028).ToString(), Bel = ((char)7).ToString(), Soh = ((char)1).ToString();
    const string Backslash = @"\";

    static string Format(string template, object value, Exception? ex = null)
    {
        var parsed = new MessageTemplateParser().Parse(template);
        var props = new[] { new LogEventProperty("V", new ScalarValue(value)) };
        var e = new LogEvent(new DateTimeOffset(2026, 11, 27, 10, 0, 0, TimeSpan.Zero), LogEventLevel.Warning, ex, parsed, props);
        using var sw = new StringWriter();
        new Logging.RedactingFormatter().Format(e, sw);
        return sw.ToString();
    }

    [Fact]
    public void A_message_with_line_breaks_stays_on_one_line()
    {
        var text = Format("Skipped {V}", "evil" + "\r\n" + "2026-11-27 10:00:00.000 +00:00 [INF] Scan finished: nothing found" + Nel + LineSep + Bel);
        var lines = text.Split(Environment.NewLine);
        Assert.Equal(2, lines.Length);                                   // the entry, then the final line break
        Assert.Equal("", lines[1]);
        Assert.Contains("evil" + Backslash + "r" + Backslash + "n" + "2026-11-27", lines[0]);
        Assert.Contains(Backslash + "u0085" + Backslash + "u2028" + Backslash + "u0007", lines[0]);
        Assert.DoesNotContain(Nel, text, StringComparison.Ordinal);          // ordinal: culture compare ignores control chars
        Assert.DoesNotContain(LineSep, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Bel, text, StringComparison.Ordinal);
    }

    [Fact]
    public void Messages_are_still_redacted_and_exceptions_keep_their_lines()
    {
        var text = Format("Run {V}", "tool --password Hunter2", new InvalidOperationException("boom" + Soh));
        Assert.Contains("--password ***", text);
        Assert.DoesNotContain("Hunter2", text);
        Assert.Contains("System.InvalidOperationException: boom" + Backslash + "u0001", text);
        Assert.DoesNotContain(Soh, text, StringComparison.Ordinal);
    }
}
