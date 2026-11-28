using System.Net;
using System.Text.RegularExpressions;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Rules every HealthReport.html must follow, whatever the PC. Each one exists because a real run broke it:
/// labels vs banner counts, verdict vs labels, "Do these things" when nothing is urgent, duplicate app rows,
/// unescaped data, scripts or links, and leaked secrets.
/// </summary>
public static partial class ReportInvariants
{
    public const string Canary = PCPorter.TestKit.OldPcDrive.Canary;

    [GeneratedRegex(@"<span class=""chip [a-z]+"">([^<]*)</span>")] private static partial Regex Chip();
    [GeneratedRegex(@"<b>(\d+)</b> worth a look")] private static partial Regex BannerLook();
    [GeneratedRegex(@"<b>(\d+)</b> unusual")] private static partial Regex BannerUnusual();
    [GeneratedRegex(@"<h1>([^<]+)</h1>")] private static partial Regex Verdict();
    [GeneratedRegex(@"<div class=""row [a-z]+"" data-level=""[A-Za-z]+""><span class=""chip")] private static partial Regex RowWithChip();
    [GeneratedRegex(@"<div class=""row ")] private static partial Regex AnyRow();
    [GeneratedRegex(@"<tr><td>([^<]*)</td><td>([^<]*)</td>")] private static partial Regex AppRow();
    [GeneratedRegex(@"<ol class=""todo"">(.*?)</ol>", RegexOptions.Singleline)] private static partial Regex TodoList();
    [GeneratedRegex(@"<\s*/?\s*([a-zA-Z][a-zA-Z0-9-]*)")] private static partial Regex AnyTag();
    /// <summary>A row of the "Checks that ran" table for a check that was stopped, failed or ran out of time.</summary>
    [GeneratedRegex(@"<tr><td>[^<]*</td><td>(Cancelled|Failed|TimedOut)</td>")] private static partial Regex IncompleteRun();
    [GeneratedRegex(@"<[^>]*\son[a-z]+\s*=", RegexOptions.IgnoreCase)] private static partial Regex EventHandler();

    /// <summary>Every tag HealthReport writes. Anything else in the file came from scanned data that was not escaped.</summary>
    static readonly HashSet<string> AllowedTags =
    [
        "html", "head", "meta", "title", "style", "body", "header", "nav", "main", "section", "footer", "h1", "h2", "h3", "p", "div",
        "span", "b", "strong", "code", "br", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "details", "summary",
        "a", "label", "input",
    ];

    public static IReadOnlyList<string> Violations(string html)
    {
        var v = new List<string>();
        var chips = Chip().Matches(html).Select(m => WebUtility.HtmlDecode(m.Groups[1].Value)).ToList();
        int look = int.Parse(BannerLook().Match(html).Groups[1].Value), unusual = int.Parse(BannerUnusual().Match(html).Groups[1].Value);
        int lookChips = chips.Count(c => c is "Worth a look" or "Fix this"), unusualChips = chips.Count(c => c == "Unusual");

        if (look != lookChips) v.Add($"Banner says {look} worth a look, but {lookChips} rows are labelled Worth a look / Fix this.");
        if (unusual != unusualChips) v.Add($"Banner says {unusual} unusual, but {unusualChips} rows are labelled Unusual.");

        var verdict = Verdict().Match(html).Groups[1].Value;
        var expected = chips.Contains("Fix this") ? "Needs attention" : chips.Contains("Worth a look") ? "Worth a look" : chips.Contains("Unusual") ? "Mostly fine" : "Looks good";
        // A stopped scan or a failed check never gets a clean bill of health.
        bool incomplete = IncompleteRun().IsMatch(html);
        if (incomplete && expected is "Looks good" or "Mostly fine") expected = "Incomplete check";
        if (verdict != expected) v.Add($"Verdict is '{verdict}' but the labels call for '{expected}'.");
        if (incomplete && !html.Contains("<p class=\"partial\">")) v.Add("A check was stopped or failed, but the summary does not say parts are missing.");
        if (Regex.IsMatch(html, @"<tr><td>[^<]*</td><td>Cancelled</td>") && !html.Contains("stopped early")) v.Add("The scan was stopped, but the summary does not say so.");

        var heading = expected switch { "Needs attention" => "Do these things", "Worth a look" => "Check these things", _ => "Worth checking when you have time" };
        if (!html.Contains($"<section id=\"todo\"><h2>{heading}</h2>"))
            v.Add($"The to-do heading should be '{heading}' for a '{expected}' report.");
        if (expected != "Looks good" && html.Contains("didn't find anything")) v.Add("Says nothing was found although items are labelled.");
        if (TodoList().Match(html) is { Success: true } todo)
        {
            if (Regex.Matches(todo.Groups[1].Value, "<li>").Count > 3) v.Add("More than 3 to-do items.");
            if (Regex.IsMatch(todo.Groups[1].Value, "No action needed|Nothing to do", RegexOptions.IgnoreCase)) v.Add("A to-do item says no action is needed.");
        }

        if (RowWithChip().Matches(html).Count != AnyRow().Matches(html).Count) v.Add("A finding row has no label.");

        int ms = html.IndexOf("id=\"moving\"", StringComparison.Ordinal), me = html.IndexOf("id=\"hardware\"", StringComparison.Ordinal);
        if (ms < 0 || me < ms) v.Add("The 'moving' and 'hardware' sections are missing or out of order, so the app list could not be checked.");
        var moving = ms >= 0 && me > ms ? html[ms..me] : "";
        var apps = AppRow().Matches(moving).Select(m => (m.Groups[1].Value.ToLowerInvariant(), m.Groups[2].Value.ToLowerInvariant())).ToList();
        if (apps.Count != apps.Distinct().Count()) v.Add("The app list has the same app (name and maker) twice.");

        if (!html.Contains("default-src 'none'")) v.Add("The strict Content-Security-Policy is missing.");
        if (html.Contains("<script", StringComparison.OrdinalIgnoreCase)) v.Add("HealthReport.html contains a <script> (data not escaped, or a script was added).");
        // Unescaped data shows up as a tag the report never writes (<img onerror=...>, <iframe>, <pcp-x>) or an event handler.
        foreach (var tag in AnyTag().Matches(html).Select(m => m.Groups[1].Value.ToLowerInvariant()).Distinct())
            if (!AllowedTags.Contains(tag)) v.Add($"Unexpected <{tag}> tag (data not escaped?).");
        if (EventHandler().IsMatch(html) || html.Contains("javascript:", StringComparison.OrdinalIgnoreCase)) v.Add("An event handler or javascript: link appears (data not escaped?).");
        if (Regex.IsMatch(html, @"(href|src)\s*=\s*""?https?:", RegexOptions.IgnoreCase)) v.Add("The report links to or loads something from the internet.");
        if (html.Contains(Canary)) v.Add("The canary secret appears in the report (redaction failed).");
        if (!html.Contains("Read-only scan. Nothing was changed or sent anywhere.")) v.Add("The read-only footer is missing.");
        if (html.Contains("class=\"partial\"") && html.Contains("didn't find anything")) v.Add("A partial scan claims nothing was found anywhere.");
        if (Regex.IsMatch(html, @"<b>1</b> apps\b|\b1 items\b|\b0 startup items are\b")) v.Add("Wrong plural or a zero-count sentence.");
        return v;
    }

    public static void AssertHolds(string html)
    {
        var v = Violations(html);
        Assert.True(v.Count == 0, "Report rules broken:\n- " + string.Join("\n- ", v));
    }
}
