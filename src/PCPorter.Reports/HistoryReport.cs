using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Reports;

/// <summary>
/// Writes History.html: one self-contained offline page (strict CSP, no network) with the scan embedded as JSON.
/// Visits are compact arrays over a shared string table (each URL and title stored once), so large histories stay
/// small; the table and chart code (report-kit.js) is inlined into the page.
/// </summary>
public static class HistoryReport
{
    const string DataPlaceholder = "__PCPORTER_DATA__";
    const string KitPlaceholder = "/*__PCPORTER_KIT__*/";
    public const string FileName = "History.html";

    static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        // The default encoder escapes <, >, & and quotes, so data cannot break out of the <script> element.
    };

    public static void Write(Stream output, HistoryScan scan, ReportMeta meta)
    {
        var template = LoadResource("Templates.History.html");
        var kit = LoadResource("Templates.report-kit.js");
        if (kit.Contains("</script", StringComparison.OrdinalIgnoreCase) || kit.Contains(DataPlaceholder, StringComparison.Ordinal))
            throw new InvalidOperationException("The report kit must not contain a closing script tag or the data placeholder.");
        int k = template.IndexOf(KitPlaceholder, StringComparison.Ordinal);
        if (k < 0) throw new InvalidOperationException("Report template is missing its kit placeholder.");
        template = template[..k] + kit + template[(k + KitPlaceholder.Length)..];
        int at = template.IndexOf(DataPlaceholder, StringComparison.Ordinal);
        if (at < 0) throw new InvalidOperationException("Report template is missing its data placeholder.");

        output.Write(Encoding.UTF8.GetBytes(template[..at]));
        WriteData(output, scan, meta);
        output.Write(Encoding.UTF8.GetBytes(template[(at + DataPlaceholder.Length)..]));
    }

    public static string Render(HistoryScan scan, ReportMeta meta)
    {
        using var ms = new MemoryStream();
        Write(ms, scan, meta);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static string WriteFile(HistoryScan scan, ReportMeta meta, string reportFolder)
    {
        var path = Path.Combine(reportFolder, FileName);
        using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        Write(fs, scan, meta);
        return path;
    }

    static void WriteData(Stream output, HistoryScan scan, ReportMeta meta)
    {
        var profiles = scan.Profiles.ToList();
        var profileIndex = new Dictionary<BrowserProfile, int>();
        for (int i = 0; i < profiles.Count; i++) profileIndex.TryAdd(profiles[i], i);
        int P(BrowserProfile p)
        {
            if (!profileIndex.TryGetValue(p, out var i)) { i = profiles.Count; profiles.Add(p); profileIndex[p] = i; }
            return i;
        }

        // String table: every visit URL, title and note once.
        var strings = new List<string>();
        var stringIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        int S(string? s)
        {
            if (s is null) return -1;
            if (!stringIndex.TryGetValue(s, out var i)) { i = strings.Count; strings.Add(s); stringIndex[s] = i; }
            return i;
        }
        var rows = scan.Visits.Select(v => (P: P(v.Profile), U: S(v.Url), T: S(v.Title), v.When, v.How, v.DurationSeconds, v.Origin, N: S(v.OriginNote))).ToList();
        static long? Unix(DateTimeOffset? t) => t?.ToUnixTimeSeconds();

        using var w = new Utf8JsonWriter(output);
        w.WriteStartObject();
        w.WritePropertyName("meta"); JsonSerializer.Serialize(w, meta, Json);
        w.WritePropertyName("notes"); JsonSerializer.Serialize(w, scan.Notes, Json);
        w.WritePropertyName("warnings"); JsonSerializer.Serialize(w, scan.Warnings, Json);
        w.WritePropertyName("howNames"); JsonSerializer.Serialize(w, Enum.GetNames<VisitHow>(), Json);
        w.WritePropertyName("originNames"); JsonSerializer.Serialize(w, Enum.GetNames<Origin>(), Json);
        // Coverage and the other lists may name profiles the visits did not: index them before writing the profile list.
        var coverage = scan.Coverage.Select(c => new { p = P(c.Profile), c.Visits, earliest = Unix(c.Earliest), latest = Unix(c.Latest), c.Note }).ToList();
        var searches = scan.Searches.Select(s => new { p = P(s.Profile), s.Terms, s.Engine, t = Unix(s.When), s.Origin }).ToList();
        var downloads = scan.Downloads.Select(d => new { p = P(d.Profile), d.Url, d.Referrer, d.TargetPath, t = Unix(d.Started), d.Bytes, d.State, onDisk = d.StillOnDisk }).ToList();
        var bookmarks = scan.Bookmarks.Select(b => new { p = P(b.Profile), b.Title, b.Url, b.Folder, t = Unix(b.Added) }).ToList();
        var tabs = scan.Tabs.Select(x => new { p = P(x.Profile), x.Url, x.Title, x.Window, x.State, t = Unix(x.LastActive) }).ToList();
        var forms = scan.Forms.Select(f => new { p = P(f.Profile), f.Field, f.Value, f.Count, first = Unix(f.First), last = Unix(f.Last) }).ToList();

        w.WritePropertyName("profiles");
        JsonSerializer.Serialize(w, profiles.Select(p => new { p.User, p.Browser, p.Family, p.Name }), Json);
        w.WritePropertyName("coverage"); JsonSerializer.Serialize(w, coverage, Json);
        w.WritePropertyName("strings"); JsonSerializer.Serialize(w, strings, Json);
        w.WritePropertyName("visits");
        w.WriteStartArray();
        foreach (var r in rows)
        {
            w.WriteStartArray();
            w.WriteNumberValue(r.P); w.WriteNumberValue(r.U); w.WriteNumberValue(r.T);
            w.WriteNumberValue(r.When.ToUnixTimeSeconds()); w.WriteNumberValue((int)r.How);
            w.WriteNumberValue(r.DurationSeconds); w.WriteNumberValue((int)r.Origin); w.WriteNumberValue(r.N);
            w.WriteEndArray();
            if (w.BytesPending > 1 << 16) w.Flush();
        }
        w.WriteEndArray();
        w.WritePropertyName("searches"); JsonSerializer.Serialize(w, searches, Json);
        w.WritePropertyName("downloads"); JsonSerializer.Serialize(w, downloads, Json);
        w.WritePropertyName("bookmarks"); JsonSerializer.Serialize(w, bookmarks, Json);
        w.WritePropertyName("tabs"); JsonSerializer.Serialize(w, tabs, Json);
        w.WritePropertyName("forms"); JsonSerializer.Serialize(w, forms, Json);
        w.WriteEndObject();
        w.Flush();
    }

    static string LoadResource(string suffix)
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith(suffix, StringComparison.Ordinal));
        using var reader = new StreamReader(asm.GetManifestResourceStream(name)!);
        return reader.ReadToEnd();
    }
}
