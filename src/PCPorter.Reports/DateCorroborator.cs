using PCPorter.Forensics.Gallery;

namespace PCPorter.Reports;

/// <summary>
/// Tightens and supports "displayed between" windows using other records:
/// - a thumbnail also present in a restore point created at D was stored before D (upper bound, confidence High);
/// - the same file opened in an app (recent files, Jump Lists) adds a supporting time line.
/// </summary>
public static class DateCorroborator
{
    public static List<GalleryItem> Apply(IReadOnlyList<GalleryItem> items)
    {
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

            // The earliest restore point that already held this entry (same user, same cache id).
            // It only tightens the window when it falls inside it; otherwise the live copy was stored again later
            // (e.g. the cache was rebuilt), so the line is supporting evidence and the window stays as it is.
            if (i.RestorePoints is { Count: > 0 } points)
            {
                var after = i.Dates.After;
                var older = points.Where(p => after is { } a && p <= a).ToList();
                var inside = points.Where(p => (after is null || p > after) && (before is null || p < before)).ToList();
                if (older.Count > 0)
                    sources.Add($"Already in a restore point from {older.Min():u}, before this cache file was created: Windows first stored the picture before then and stored it again later");
                if (inside.Count > 0)
                {
                    before = inside.Min();
                    confidence = "High";
                    sources.Add($"Already in a restore point from {before:u} (the picture was stored before this)");
                }
                else if (older.Count == 0)
                    sources.Add($"Also in a restore point from {points.Min():u}");
            }
            if (i.OriginalPath is not null && opens.TryGetValue(i.OriginalPath, out var opened))
                foreach (var o in opened.Take(5))
                    sources.Add($"Same file opened in an app: {o.Source}, {o.Dates!.Before:u}");

            result.Add(sources.Count == i.Dates.Sources.Count ? i : i with { Dates = i.Dates with { Before = before, Confidence = confidence, Sources = sources } });
        }
        return result;
    }
}
