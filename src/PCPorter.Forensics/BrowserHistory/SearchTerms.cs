using System.Text.RegularExpressions;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>Recognises the search terms in a search engine's result-page address.</summary>
public static class SearchTerms
{
    /// <summary>Engine, host pattern (registrable name plus country suffixes), path rule, query parameters.</summary>
    static readonly (string Engine, Regex Host, Func<string, bool> Path, string[] Params)[] Engines =
    [
        ("Google", Host("google"), p => p.StartsWith("/search", StringComparison.OrdinalIgnoreCase), ["q"]),
        ("Bing", Host("bing"), p => p.StartsWith("/search", StringComparison.OrdinalIgnoreCase), ["q"]),
        ("DuckDuckGo", Host("duckduckgo"), _ => true, ["q"]),
        ("Yahoo", Host("yahoo"), p => p.StartsWith("/search", StringComparison.OrdinalIgnoreCase), ["p"]),
        ("YouTube", Host("youtube"), p => p.StartsWith("/results", StringComparison.OrdinalIgnoreCase), ["search_query"]),
        ("Ecosia", Host("ecosia"), p => p.StartsWith("/search", StringComparison.OrdinalIgnoreCase), ["q"]),
        ("Startpage", Host("startpage"), p => p.Contains("search", StringComparison.OrdinalIgnoreCase), ["query", "q"]),
        ("Brave Search", new Regex(@"^search\.brave\.com$", RegexOptions.IgnoreCase), p => p.StartsWith("/search", StringComparison.OrdinalIgnoreCase), ["q"]),
        ("Amazon", Host("amazon"), p => p.Equals("/s", StringComparison.OrdinalIgnoreCase) || p.StartsWith("/s/", StringComparison.OrdinalIgnoreCase), ["k"]),
        ("Wikipedia", Host("wikipedia"), _ => true, ["search"]),
    ];

    /// <summary>name.tld, name.co.uk, name.com.au and any sub-domain of those (www., en., search., m.).</summary>
    static Regex Host(string name) =>
        new($@"(^|\.){name}\.([a-z]{{2,3}}|(co|com|org|ne|or)\.[a-z]{{2}})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static (string Engine, string Terms)? FromUrl(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        if (u.Scheme is not ("http" or "https")) return null;
        foreach (var (engine, host, path, names) in Engines)
        {
            if (!host.IsMatch(u.Host) || !path(u.AbsolutePath)) continue;
            foreach (var name in names)
                if (Query(u.Query, name) is { Length: > 0 } terms) return (engine, terms);
            return null;
        }
        return null;
    }

    static string? Query(string query, string name)
    {
        foreach (var part in query.TrimStart('?').Split('&'))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0 || !part[..eq].Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            try { return Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' ')).Trim(); }
            catch (UriFormatException) { return null; }
        }
        return null;
    }
}
