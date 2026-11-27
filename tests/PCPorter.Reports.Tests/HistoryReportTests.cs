using System.Text.Json;
using System.Text.RegularExpressions;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class HistoryReportTests
{
    static readonly ReportMeta Meta = new("BOB-LAPTOP", new DateTimeOffset(2026, 11, 26, 12, 0, 0, TimeSpan.Zero), "0.1.0", ["bob"], false);
    static readonly DateTimeOffset T0 = new(2026, 3, 1, 10, 0, 0, TimeSpan.Zero);
    static readonly BrowserProfile Chrome = new("bob", "Google Chrome", BrowserFamily.Chromium, "Default", @"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default");
    static readonly BrowserProfile Edge = new("bob", "Microsoft Edge", BrowserFamily.Chromium, "Work", @"C:\Users\bob\AppData\Local\Microsoft\Edge\User Data\Profile 1");

    static HistoryScan Scan(string url = "https://example.com/", string? title = "Example")
    {
        Visit[] visits =
        [
            new(Chrome, url, title, T0, VisitHow.Typed, 12),
            new(Chrome, url, title, T0.AddMinutes(5), VisitHow.Reload, 0),
            new(Edge, "https://news.example.org/", null, T0.AddHours(1), VisitHow.Link, 3, Origin.Carved, "recovered (deleted)"),
        ];
        return new HistoryScan([Chrome, Edge],
            [new ProfileCoverage(Chrome, 2, T0, T0.AddMinutes(5), "Chrome-family browsers keep about 90 days."), new ProfileCoverage(Edge, 1, T0.AddHours(1), T0.AddHours(1), "")],
            visits,
            [new Search(Chrome, "cheap flights", "Google", T0)],
            [new Download(Edge, "https://vendor.example/setup.exe", "https://vendor.example/", @"C:\Users\bob\Downloads\setup.exe", T0, 1000, DownloadState.Complete, true)],
            [new Bookmark(Chrome, "Tea shop", "https://tea.example/", "Bookmarks bar/Shops", T0.AddDays(-3))],
            [new OpenTab(Chrome, "https://open.example/", "Open", 1, TabState.Open, T0), new OpenTab(Edge, "https://gone.example/", null, 0, TabState.RecentlyClosed, null)],
            [new FormEntry(Chrome, "email", "bob@example.com", 4, T0.AddDays(-9), T0)],
            ["a note"], ["a warning"]);
    }

    [Fact]
    public void Bookmarks_tabs_and_form_entries_are_embedded()
    {
        using var doc = EmbeddedData(HistoryReport.Render(Scan(), Meta));
        var root = doc.RootElement;
        var b = root.GetProperty("bookmarks")[0];
        Assert.Equal(("Tea shop", "https://tea.example/", "Bookmarks bar/Shops", T0.AddDays(-3).ToUnixTimeSeconds()),
            (b.GetProperty("title").GetString(), b.GetProperty("url").GetString(), b.GetProperty("folder").GetString(), b.GetProperty("t").GetInt64()));
        var tabs = root.GetProperty("tabs");
        Assert.Equal(2, tabs.GetArrayLength());
        Assert.Equal(("Open", 1, T0.ToUnixTimeSeconds()), (tabs[0].GetProperty("state").GetString(), tabs[0].GetProperty("window").GetInt32(), tabs[0].GetProperty("t").GetInt64()));
        Assert.Equal(("RecentlyClosed", 1), (tabs[1].GetProperty("state").GetString(), tabs[1].GetProperty("p").GetInt32()));
        Assert.False(tabs[1].TryGetProperty("t", out _));
        var f = root.GetProperty("forms")[0];
        Assert.Equal(("email", "bob@example.com", 4, T0.ToUnixTimeSeconds()),
            (f.GetProperty("field").GetString(), f.GetProperty("value").GetString(), f.GetProperty("count").GetInt32(), f.GetProperty("last").GetInt64()));
    }

    [Fact]
    public void Form_entries_stay_collapsed_until_clicked()
    {
        var html = HistoryReport.Render(Scan(), Meta);
        var m = Regex.Match(html, "<details[^>]*id=\"forms-box\"[^>]*>");
        Assert.True(m.Success);
        Assert.DoesNotContain(" open", m.Value);
        Assert.Contains("addEventListener(\"toggle\", showForms)", html);        // the table is built only when opened
    }

    static JsonDocument EmbeddedData(string html)
    {
        var m = Regex.Match(html, "<script type=\"application/json\" id=\"data\">(.*?)</script>", RegexOptions.Singleline);
        Assert.True(m.Success, "data block missing");
        return JsonDocument.Parse(m.Groups[1].Value);
    }

    [Fact]
    public void Visits_are_compact_rows_over_a_shared_string_table()
    {
        using var doc = EmbeddedData(HistoryReport.Render(Scan(), Meta));
        var root = doc.RootElement;
        var strings = root.GetProperty("strings").EnumerateArray().Select(s => s.GetString()).ToList();
        Assert.Equal(strings.Count, strings.Distinct().Count());                 // each string stored once
        var how = root.GetProperty("howNames").EnumerateArray().Select(s => s.GetString()).ToList();
        var origin = root.GetProperty("originNames").EnumerateArray().Select(s => s.GetString()).ToList();
        var visits = root.GetProperty("visits").EnumerateArray().ToList();
        Assert.Equal(3, visits.Count);

        var v = visits[0].EnumerateArray().ToList();
        Assert.Equal(0, v[0].GetInt32());                                         // profile index
        Assert.Equal("https://example.com/", strings[v[1].GetInt32()]);
        Assert.Equal("Example", strings[v[2].GetInt32()]);
        Assert.Equal(T0.ToUnixTimeSeconds(), v[3].GetInt64());
        Assert.Equal("Typed", how[v[4].GetInt32()]);
        Assert.Equal(12, v[5].GetInt64());
        Assert.Equal("Live", origin[v[6].GetInt32()]);
        Assert.Equal(-1, v[7].GetInt32());                                        // no note
        Assert.Equal(visits[1][1].GetInt32(), v[1].GetInt32());                   // same URL, same index

        var carved = visits[2].EnumerateArray().ToList();
        Assert.Equal(1, carved[0].GetInt32());
        Assert.Equal(-1, carved[2].GetInt32());                                   // no title
        Assert.Equal("Carved", origin[carved[6].GetInt32()]);
        Assert.Equal("recovered (deleted)", strings[carved[7].GetInt32()]);

        var profiles = root.GetProperty("profiles");
        Assert.Equal("Microsoft Edge", profiles[1].GetProperty("browser").GetString());
        Assert.Equal("Work", profiles[1].GetProperty("name").GetString());
        Assert.Equal(2, root.GetProperty("coverage")[0].GetProperty("visits").GetInt32());
        Assert.Equal("cheap flights", root.GetProperty("searches")[0].GetProperty("terms").GetString());
        Assert.True(root.GetProperty("downloads")[0].GetProperty("onDisk").GetBoolean());
        Assert.Equal("Complete", root.GetProperty("downloads")[0].GetProperty("state").GetString());
        Assert.Equal("a note", root.GetProperty("notes")[0].GetString());
        Assert.Equal("a warning", root.GetProperty("warnings")[0].GetString());
        Assert.Equal("BOB-LAPTOP", root.GetProperty("meta").GetProperty("computer").GetString());
    }

    [Fact]
    public void Hostile_urls_and_titles_stay_inside_the_data_block()
    {
        var html = HistoryReport.Render(Scan("https://e.com/</script><script>alert(1)</script>", "</script><script>alert(2)</script>"), Meta);
        Assert.DoesNotContain("<script>alert(", html);
        using var doc = EmbeddedData(html);
        var strings = doc.RootElement.GetProperty("strings").EnumerateArray().Select(s => s.GetString()).ToList();
        Assert.Contains("https://e.com/</script><script>alert(1)</script>", strings);
        Assert.Contains("</script><script>alert(2)</script>", strings);
    }

    [Fact]
    public void Report_loads_nothing_from_the_network_and_has_a_strict_policy()
    {
        var html = HistoryReport.Render(Scan(), Meta);
        Assert.DoesNotMatch(@"(src|href)\s*=\s*[""']?\s*(https?:|//)", html);
        Assert.Contains("default-src 'none'", html);
        Assert.Contains("base-uri 'none'", html);
        Assert.Contains("form-action 'none'", html);
        Assert.DoesNotContain("__PCPORTER_DATA__", html);
        Assert.DoesNotContain("__PCPORTER_KIT__", html);
        Assert.Contains("function vtable", html);                                  // the kit is inlined
        Assert.DoesNotContain("innerHTML", html);
        Assert.DoesNotContain("fetch(", html);
        Assert.DoesNotContain("XMLHttpRequest", html);
    }

    [Fact]
    public void An_empty_scan_still_renders()
    {
        var empty = new HistoryScan([], [], [], [], [], [], [], [], [], []);
        using var doc = EmbeddedData(HistoryReport.Render(empty, Meta));
        Assert.Equal(0, doc.RootElement.GetProperty("visits").GetArrayLength());
    }

    [Fact]
    public void WriteFile_refuses_to_overwrite()
    {
        var dir = Directory.CreateTempSubdirectory("pcporter-history").FullName;
        try
        {
            var path = HistoryReport.WriteFile(Scan(), Meta, dir);
            Assert.Equal("History.html", Path.GetFileName(path));
            Assert.True(new FileInfo(path).Length > 1000);
            Assert.Throws<IOException>(() => HistoryReport.WriteFile(Scan(), Meta, dir));
        }
        finally { Directory.Delete(dir, true); }
    }
}
