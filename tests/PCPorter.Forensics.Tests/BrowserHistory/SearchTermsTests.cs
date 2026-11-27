using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class SearchTermsTests
{
    [Theory]
    [InlineData("https://www.google.com/search?q=cheap+flights&oq=cheap", "Google", "cheap flights")]
    [InlineData("https://www.google.co.uk/search?client=x&q=tea%20time", "Google", "tea time")]
    [InlineData("https://google.de/search?q=wetter", "Google", "wetter")]
    [InlineData("https://www.google.com.au/search?q=koala", "Google", "koala")]
    [InlineData("https://www.bing.com/search?q=windows+11&form=QBLH", "Bing", "windows 11")]
    [InlineData("https://duckduckgo.com/?q=privacy&ia=web", "DuckDuckGo", "privacy")]
    [InlineData("https://search.yahoo.com/search?p=weather", "Yahoo", "weather")]
    [InlineData("https://www.youtube.com/results?search_query=cat+videos", "YouTube", "cat videos")]
    [InlineData("https://www.ecosia.org/search?method=index&q=trees", "Ecosia", "trees")]
    [InlineData("https://www.startpage.com/sp/search?query=quiet", "Startpage", "quiet")]
    [InlineData("https://www.startpage.com/do/search?q=other", "Startpage", "other")]
    [InlineData("https://search.brave.com/search?q=lion", "Brave Search", "lion")]
    [InlineData("https://www.amazon.co.uk/s?k=usb+cable", "Amazon", "usb cable")]
    [InlineData("https://en.wikipedia.org/w/index.php?search=Ada+Lovelace", "Wikipedia", "Ada Lovelace")]
    public void Recognises_searches(string url, string engine, string terms) =>
        Assert.Equal((engine, terms), SearchTerms.FromUrl(url));

    [Theory]
    [InlineData("https://www.google.com/url?q=https://example.com/")]   // a redirect link, not a search
    [InlineData("https://www.google.com/search?q=")]
    [InlineData("https://notgoogle.com/search?q=x")]
    [InlineData("https://www.google.evil.example/search?q=x")]
    [InlineData("https://example.com/?q=x")]
    [InlineData("not a url")]
    [InlineData("")]
    public void Ignores_everything_else(string url) => Assert.Null(SearchTerms.FromUrl(url));
}
