using System.Text.Json;
using System.Text.RegularExpressions;
using PCPorter.Collectors.Sources;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Finds the browser profiles inside one Windows user profile folder. Only folder listings and file-exists checks
/// (plus Chromium's small Local State file for profile names) go through <see cref="SourceFiles"/>; nothing is opened
/// for writing and browsers are never started.
/// </summary>
public static partial class BrowserProfileFinder
{
    public const string WebCacheBrowser = "Internet Explorer / Edge (legacy)";

    static readonly (string Browser, string Root)[] ChromiumRoots =
    [
        ("Google Chrome", @"AppData\Local\Google\Chrome\User Data"),
        ("Microsoft Edge", @"AppData\Local\Microsoft\Edge\User Data"),
        ("Brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"AppData\Local\Vivaldi\User Data"),
        ("Chromium", @"AppData\Local\Chromium\User Data"),
    ];

    /// <summary>Opera keeps a single profile in the root folder itself.</summary>
    static readonly (string Browser, string Root)[] OperaRoots =
    [
        ("Opera", @"AppData\Roaming\Opera Software\Opera Stable"),
        ("Opera GX", @"AppData\Roaming\Opera Software\Opera GX Stable"),
    ];

    const string FirefoxProfiles = @"AppData\Roaming\Mozilla\Firefox\Profiles";
    const string WebCacheFolder = @"AppData\Local\Microsoft\Windows\WebCache";
    const long LocalStateCap = 1 << 20;

    [GeneratedRegex(@"^(Default|Profile \d+)$", RegexOptions.IgnoreCase)]
    private static partial Regex ChromiumProfileDir();

    public static IReadOnlyList<BrowserProfile> Find(string user, string profileFolder, IList<string> warnings)
    {
        var found = new List<BrowserProfile>();

        foreach (var (browser, rel) in ChromiumRoots)
        {
            var root = Path.Combine(profileFolder, rel);
            var dirs = SourceFiles.Folders(root)
                .Where(d => ChromiumProfileDir().IsMatch(Path.GetFileName(d)) && FileExists(Path.Combine(d, "History")))
                .ToList();
            if (dirs.Count == 0) continue;
            var names = ProfileNames(Path.Combine(root, "Local State"), browser, user, warnings);
            foreach (var d in dirs)
            {
                var dir = Path.GetFileName(d);
                found.Add(new BrowserProfile(user, browser, BrowserFamily.Chromium, names.GetValueOrDefault(dir) ?? dir, d));
            }
        }

        foreach (var (browser, rel) in OperaRoots)
        {
            var root = Path.Combine(profileFolder, rel);
            if (FileExists(Path.Combine(root, "History")))
                found.Add(new BrowserProfile(user, browser, BrowserFamily.Chromium, "Default", root));
        }

        foreach (var d in SourceFiles.Folders(Path.Combine(profileFolder, FirefoxProfiles)))
        {
            if (!FileExists(Path.Combine(d, "places.sqlite"))) continue;
            var dir = Path.GetFileName(d);
            int dot = dir.IndexOf('.');
            found.Add(new BrowserProfile(user, "Firefox", BrowserFamily.Firefox, dot >= 0 && dot < dir.Length - 1 ? dir[(dot + 1)..] : dir, d));
        }

        var webCache = Path.Combine(profileFolder, WebCacheFolder);
        if (FileExists(Path.Combine(webCache, "WebCacheV01.dat")))
            found.Add(new BrowserProfile(user, WebCacheBrowser, BrowserFamily.WebCache, "Default", webCache));

        return found
            .OrderBy(p => p.Browser, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Folder, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>True when the file exists and really lies inside the confined drive.</summary>
    internal static bool FileExists(string path) => File.Exists(path) && SourceFiles.IsInside(path);

    /// <summary>
    /// Profile display names from Local State's <c>profile.info_cache</c>. Only that branch is looked at (the file
    /// also holds the browser's encryption key, which is never read out), and the bytes are wiped after parsing.
    /// </summary>
    static Dictionary<string, string> ProfileNames(string localState, string browser, string user, IList<string> warnings)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!FileExists(localState)) return names;
        byte[]? bytes = null;
        try
        {
            bytes = SourceFiles.ReadAllBytes(localState, LocalStateCap);
            var json = bytes.AsMemory();
            if (json.Span.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) json = json[3..];
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("profile", out var profile) && profile.ValueKind == JsonValueKind.Object
                && profile.TryGetProperty("info_cache", out var cache) && cache.ValueKind == JsonValueKind.Object)
                foreach (var p in cache.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("name", out var n)
                        && n.ValueKind == JsonValueKind.String && n.GetString() is { Length: > 0 } name)
                        names[p.Name] = name;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            warnings.Add($"{browser} profile names for {user} could not be read; folder names are shown instead.");
        }
        finally { if (bytes is not null) Array.Clear(bytes); }
        return names;
    }
}
