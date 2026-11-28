using PCPorter.Reports;

namespace PCPorter.Reports.Tests.Regression;

/// <summary>
/// Tier 2 regression: each made-up PC is scanned (fixed collectors), its HealthReport is rendered with a fixed time,
/// checked against the report rules, and compared with its golden text file.
/// </summary>
public class ReportRegressionTests : IDisposable
{
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-regress").FullName;
    public void Dispose() { try { Directory.Delete(_out, true); } catch (IOException) { } }

    public static TheoryData<string> Pcs() => new(SyntheticPcs.All().Select(p => p.Name));

    static readonly DateTimeOffset FixedTime = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Golden files are rendered in en-US so they read the same on any PC; other cultures get the rule checks.</summary>
    (ScanJobResult Result, string Html) Render(string name, string culture = "en-US")
    {
        var saved = (System.Globalization.CultureInfo.CurrentCulture, System.Globalization.CultureInfo.CurrentUICulture);
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.CurrentUICulture = new System.Globalization.CultureInfo(culture);
        try { return RenderNow(name); }
        finally { (System.Globalization.CultureInfo.CurrentCulture, System.Globalization.CultureInfo.CurrentUICulture) = saved; }
    }

    (ScanJobResult Result, string Html) RenderNow(string name)
    {
        var pc = SyntheticPcs.All().Single(p => p.Name == name);
        var r = ScanJob.Run(_out, new ScanJobOptions(), _ => pc.Collectors, ct: pc.Stop?.Token ?? default);
        // Make the report independent of the machine running the test: no host name, no host notes.
        r = r with { ScannedComputer = null, SourceNotes = [], Offline = pc.Offline };
        return (r, HealthReport.Render(r, FixedTime));
    }

    [Theory, MemberData(nameof(Pcs))]
    public void Report_follows_the_rules(string pc) => ReportInvariants.AssertHolds(Render(pc).Html);

    /// <summary>A home PC set to German or French formats numbers and dates differently: the rules must still hold.</summary>
    [Theory, MemberData(nameof(Pcs))]
    public void Report_follows_the_rules_in_other_languages(string pc)
    {
        ReportInvariants.AssertHolds(Render(pc, "de-DE").Html);
        ReportInvariants.AssertHolds(Render(pc, "fr-FR").Html);
    }

    [Theory, MemberData(nameof(Pcs))]
    public void Report_text_matches_golden(string pc) => Golden.Check("health-" + pc, ReportText.Extract(Render(pc).Html));

    [Theory, MemberData(nameof(Pcs))]
    public void Cli_and_app_counts_equal_the_banner(string pc)
    {
        var (r, html) = Render(pc);
        var f = ScanSetup.CountFindings(r);
        Assert.Contains($"<b>{f.WorthALook}</b> worth a look", html);
        Assert.Contains($"<b>{f.Unusual}</b> unusual", html);
    }

    [Fact]
    public void Expected_verdicts()
    {
        var verdicts = SyntheticPcs.All().ToDictionary(p => p.Name, p => System.Text.RegularExpressions.Regex.Match(Render(p.Name).Html, "<h1>([^<]+)</h1>").Groups[1].Value);
        Assert.Equal("Looks good", verdicts["clean"]);
        Assert.Equal("Worth a look", verdicts["looks-infected"]);
        Assert.Equal("Needs attention", verdicts["no-protection"]);
        Assert.Equal("Needs attention", verdicts["failing-hardware"]);
        Assert.Equal("Looks good", verdicts["dead-drive-offline"]);
        Assert.Equal(SyntheticPcs.All().Count(), verdicts.Count);
        Assert.Equal("Incomplete check", verdicts["partial-scan"]);   // a check failed: never "Looks good"
        Assert.Equal("Incomplete check", verdicts["stopped-early"]);  // the user stopped it
    }

    /// <summary>The rule checker itself must catch the bugs it exists for (otherwise it could silently pass everything).</summary>
    [Fact]
    public void The_rule_checker_catches_known_bugs()
    {
        var good = Render("looks-infected").Html;
        Assert.Empty(ReportInvariants.Violations(good));
        Assert.NotEmpty(ReportInvariants.Violations(System.Text.RegularExpressions.Regex.Replace(good, @"<b>\d+</b> worth a look", "<b>0</b> worth a look")));   // banner vs labels
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("<h1>Worth a look</h1>", "<h1>Mostly fine</h1>")));              // verdict vs labels
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("<h2>Check these things</h2>", "<h2>Do these things</h2>")));     // heading vs verdict
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("</footer>", $"{ReportInvariants.Canary}</footer>")));          // leaked secret
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("</footer>", "<script>x()</script></footer>")));
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("</footer>", "<img src=x onerror=alert(1)></footer>")));   // unescaped tag + handler
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("</footer>", "<pcp-x></pcp-x></footer>")));               // unknown tag
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("</footer>", "<a href=\"https://evil.example\">x</a></footer>")));   // internet link
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("Read-only scan. Nothing was changed", "Scan")));                 // footer
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("<ol class=\"todo\">", "<ol class=\"todo\"><li>a</li><li>b</li><li>c</li><li>d</li>")));   // > 3 to-dos
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("<ol class=\"todo\">", "<ol class=\"todo\"><li>No action needed.</li>")));
        Assert.NotEmpty(ReportInvariants.Violations(good.Replace("id=\"hardware\"", "id=\"hw\"")));                              // app check would be skipped
        Assert.NotEmpty(ReportInvariants.Violations(System.Text.RegularExpressions.Regex.Replace(good, @"<span class=""chip [a-z]+"">[^<]*</span>", "", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1))));   // unlabelled rows
        var clean = Render("clean").Html;
        Assert.NotEmpty(ReportInvariants.Violations(clean.Replace("<tr><td>7-Zip</td>", "<tr><td>Family Recipes</td><td>Small Shop</td><td></td><td></td></tr><tr><td>7-Zip</td>")));   // duplicate app
        var stopped = Render("stopped-early").Html;
        Assert.Empty(ReportInvariants.Violations(stopped));
        Assert.NotEmpty(ReportInvariants.Violations(stopped.Replace("<h1>Incomplete check</h1>", "<h1>Looks good</h1>")));      // stopped scan, clean verdict
        Assert.NotEmpty(ReportInvariants.Violations(stopped.Replace("stopped early", "not finished")));                           // stop not called out
    }
}
