using System.Globalization;
using System.Text.RegularExpressions;
using PCPorter.Forensics.Gallery;

namespace PCPorter.Reports;

/// <summary>
/// Tightens and supports "displayed between" windows using other records:
/// - a thumbnail also present in a restore point dated D was stored before D (upper bound, confidence High);
/// - the same file opened in an app (recent files, Jump Lists) adds a supporting time line.
/// </summary>
public static partial class DateCorroborator
{
    [GeneratedRegex(@"^(?<user>.+) \(restore point (?<date>\d{4}-\d{2}-\d{2})\)$")]
    private static partial Regex RestorePointUser();

    public static List<GalleryItem> Apply(IReadOnlyList<GalleryItem> items)
    {
        // Earliest restore point that already held each (user, cache id).
        var earliestRestore = new Dictionary<(string, string), DateTimeOffset>();
        foreach (var i in items)
        {
            if (i.CacheId is null || RestorePointUser().Match(i.User) is not { Success: true } m) continue;
            var date = DateTimeOffset.ParseExact(m.Groups["date"].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).AddDays(1);
            var key = (m.Groups["user"].Value, i.CacheId);
            if (!earliestRestore.TryGetValue(key, out var d) || date < d) earliestRestore[key] = date;
        }

        var opens = items.Where(i => i.Kind == "opened" && i.OriginalPath is not null && i.Dates is not null)
            .GroupBy(i => i.OriginalPath!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var result = new List<GalleryItem>(items.Count);
        foreach (var i in items)
        {
            if (i.Kind != "thumbnail" || i.Dates is null) { result.Add(i); continue; }
            var sources = i.Dates.Sources.ToList();
            var before = i.Dates.Before;
            var confidence = i.Dates.Confidence;

            if (i.CacheId is not null && earliestRestore.TryGetValue((i.User, i.CacheId), out var restore) && (before is null || restore < before))
            {
                before = restore;
                sources.Add($"Already in a restore point from {restore.AddDays(-1):yyyy-MM-dd} (the picture was stored before this)");
                confidence = "High";
            }
            if (i.OriginalPath is not null && opens.TryGetValue(i.OriginalPath, out var opened))
                foreach (var o in opened.Take(5))
                    sources.Add($"Same file opened in an app: {o.Source}, {o.Dates!.Before:u}");

            result.Add(sources.Count == i.Dates.Sources.Count ? i : i with { Dates = i.Dates with { Before = before, Confidence = confidence, Sources = sources } });
        }
        return result;
    }
}
