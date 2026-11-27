using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>Reads a Chromium profile's "Bookmarks" JSON file (bookmarks bar, other and mobile bookmarks, with folders).</summary>
public static class ChromiumBookmarks
{
    static readonly (string Key, string Label)[] Roots =
    [
        ("bookmark_bar", "Bookmarks bar"),
        ("other", "Other bookmarks"),
        ("synced", "Mobile bookmarks"),
    ];

    const int MaxDepth = 100;

    public static List<Bookmark> Read(BrowserProfile profile)
    {
        var path = Path.Combine(profile.Folder, "Bookmarks");
        if (!BrowserProfileFinder.FileExists(path)) return [];
        return Parse(profile, SourceFiles.ReadAllBytes(path));
    }

    public static List<Bookmark> Parse(BrowserProfile profile, ReadOnlyMemory<byte> json)
    {
        if (json.Span.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) json = json[3..];
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 2 * MaxDepth + 16, AllowTrailingCommas = true });
        var list = new List<Bookmark>();
        if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("roots", out var roots)
            || roots.ValueKind != JsonValueKind.Object) return list;
        foreach (var (key, label) in Roots)
            if (roots.TryGetProperty(key, out var root) && root.ValueKind == JsonValueKind.Object)
                Children(profile, root, label, 0, list);
        return list;
    }

    static void Children(BrowserProfile profile, JsonElement folder, string path, int depth, List<Bookmark> list)
    {
        if (depth > MaxDepth || !folder.TryGetProperty("children", out var children) || children.ValueKind != JsonValueKind.Array) return;
        foreach (var node in children.EnumerateArray())
        {
            if (node.ValueKind != JsonValueKind.Object) continue;
            var type = Text(node, "type");
            var name = Text(node, "name") ?? "";
            if (type == "url" && Text(node, "url") is { Length: > 0 } url)
                list.Add(new Bookmark(profile, Redactor.Redact(name), Redactor.Redact(url), path, Added(node)));
            else if (type == "folder")
                Children(profile, node, path + "/" + Redactor.Redact(name), depth + 1, list);
        }
    }

    static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>date_added: WebKit microseconds stored as a decimal string.</summary>
    static DateTimeOffset? Added(JsonElement node) =>
        Text(node, "date_added") is { } s && long.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var micros)
            ? Timestamps.FromWebKit(micros) : null;
}
