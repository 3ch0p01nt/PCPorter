using System.Net;
using System.Text.RegularExpressions;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Golden-file check: compares text with tests/PCPorter.Reports.Tests/Golden/&lt;name&gt;.txt.
/// Run scripts/regress.ps1 -Accept (sets PCPORTER_ACCEPT=1) to (re)write the golden files, then review the change with git diff.
/// On a mismatch the new text is written next to the golden file as &lt;name&gt;.received.txt (git-ignored).
/// </summary>
public static class Golden
{
    public static string Folder { get; } = FindFolder();

    static string FindFolder()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "PCPorter.Reports.Tests.csproj"))) return Path.Combine(d.FullName, "Golden");
        throw new InvalidOperationException("Could not find the PCPorter.Reports.Tests project folder.");
    }

    public static void Check(string name, string actual)
    {
        Directory.CreateDirectory(Folder);
        var golden = Path.Combine(Folder, name + ".txt");
        var received = Path.Combine(Folder, name + ".received.txt");
        actual = actual.Replace("\r\n", "\n");
        if (Environment.GetEnvironmentVariable("PCPORTER_ACCEPT") == "1")
        {
            File.WriteAllText(golden, actual);
            if (File.Exists(received)) File.Delete(received);
            return;
        }
        if (!File.Exists(golden))
        {
            File.WriteAllText(received, actual);
            Assert.Fail($"No golden file for '{name}'. Review {received}, then run scripts/regress.ps1 -Accept to accept it.");
        }
        var expected = File.ReadAllText(golden).Replace("\r\n", "\n");
        if (expected == actual) { if (File.Exists(received)) File.Delete(received); return; }
        File.WriteAllText(received, actual);
        var e = expected.Split('\n'); var a = actual.Split('\n');
        int i = 0;
        while (i < e.Length && i < a.Length && e[i] == a[i]) i++;
        Assert.Fail($"'{name}' changed at line {i + 1}:\n  golden:   {(i < e.Length ? e[i] : "<end>")}\n  received: {(i < a.Length ? a[i] : "<end>")}\n" +
                    $"Compare {golden} with {received}. If the change is intended, run scripts/regress.ps1 -Accept.");
    }
}

/// <summary>A stable, readable text view of HealthReport.html for golden files: labels, titles, text, app rows.</summary>
public static partial class ReportText
{
    [GeneratedRegex(@"<style>.*?</style>", RegexOptions.Singleline)] private static partial Regex Style();
    [GeneratedRegex(@"<span class=""chip [a-z]+"">([^<]*)</span>")] private static partial Regex Chip();
    [GeneratedRegex(@"</(p|li|tr|h1|h2|h3|summary|div|header|section|footer|ul|ol|table|thead|tbody)>|<br\s*/?>")] private static partial Regex BlockEnd();
    [GeneratedRegex(@"</t[dh]>")] private static partial Regex CellEnd();
    [GeneratedRegex(@"<[^>]+>")] private static partial Regex Tag();
    [GeneratedRegex(@"^Scanned .*$")] private static partial Regex Scanned();
    [GeneratedRegex(@"\b\d+\.\d s\b")] private static partial Regex Seconds();
    [GeneratedRegex(@"^Scan [0-9a-f]{12}\.")] private static partial Regex ScanId();

    public static string Extract(string html)
    {
        var start = html.IndexOf("<main", StringComparison.Ordinal);
        var s = Style().Replace(start >= 0 ? html[start..] : html, "");
        s = Chip().Replace(s, m => $"[{m.Groups[1].Value}] ");
        s = s.Replace("</b><p>", "</b>: <p>").Replace("</b></label><p>", "</b>: <p>");   // "Title: text" on one line
        s = BlockEnd().Replace(s, "\n");
        s = CellEnd().Replace(s, " | ");
        s = WebUtility.HtmlDecode(Tag().Replace(s, ""));
        var lines = s.Split('\n')
            .Select(l => Regex.Replace(l, @"\s+", " ").Trim().TrimEnd('|').Trim())
            .Where(l => l.Length > 0)
            .Select(l => Scanned().Replace(l, "Scanned <time>"))
            .Select(l => Seconds().Replace(l, "#.# s"))
            .Select(l => ScanId().Replace(l, "Scan <id>."));
        return string.Join('\n', lines) + "\n";
    }
}
