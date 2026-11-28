using PCPorter.App.Views;
using PCPorter.Core.Case;

namespace PCPorter.App.Tests;

public class OtherPcResultsTests
{
    static readonly FoundCase Case = new(@"E:\PCPorter\OLD-PC_20261127T100000Z_abcdef", "OLD-PC",
        new DateTimeOffset(2026, 11, 27, 10, 0, 0, TimeSpan.Zero), ["Health and security"], true);

    [Fact]
    public void Nothing_found_says_what_to_do()
    {
        var text = HomePage.Summary(new CaseSearch([], []), "on the connected drives", elevated: true);
        Assert.Contains("No PCPorter results were found on the connected drives.", text);
        Assert.Contains("Connect the backup drive", text);
    }

    [Fact]
    public void Locked_results_without_administrator_say_to_start_as_administrator()
    {
        var text = HomePage.Summary(new CaseSearch([], [@"E:\PCPorter"]), "the connected drives", elevated: false);
        Assert.Contains("locked to another account", text);
        Assert.Contains("administrator", text);
        Assert.Contains("administrator", HomePage.Summary(new CaseSearch([Case], [@"F:\PCPorter"]), "x", elevated: false));
        Assert.DoesNotContain("administrator", HomePage.Summary(new CaseSearch([Case], []), "x", elevated: false));
    }

    [Fact]
    public void Found_results_are_counted_and_listed_with_pc_and_reports()
    {
        Assert.StartsWith("1 set of results found", HomePage.Summary(new CaseSearch([Case], []), "x", elevated: true));
        Assert.StartsWith("2 sets of results found", HomePage.Summary(new CaseSearch([Case, Case], []), "x", elevated: true));
        Assert.StartsWith("OLD-PC, ", Case.ToString());
        Assert.EndsWith("- Health and security (E:)", Case.ToString());
    }
}
