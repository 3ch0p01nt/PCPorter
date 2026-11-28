using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PCPorter.Forensics.Gallery;

namespace PCPorter.Reports;

public sealed record ReportMeta(string Computer, DateTimeOffset GeneratedUtc, string ToolVersion, IReadOnlyList<string> Users, bool AllUsers);

/// <summary>
/// Writes Thumbnails.html: a self-contained offline gallery (no network, strict CSP) that loads images from the
/// sibling folder. The data is streamed into the page, so large cases don't need several in-memory copies.
/// </summary>
public static class GalleryReport
{
    const string Placeholder = "__PCPORTER_DATA__";

    static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        // The default encoder escapes <, >, & and quotes, so data cannot break out of the <script> element.
    };

    public static void Write(Stream output, GalleryScanResult result, ReportMeta meta, string imagesFolderName)
    {
        var template = LoadTemplate();
        int at = template.IndexOf(Placeholder, StringComparison.Ordinal);
        if (at < 0) throw new InvalidOperationException("Report template is missing its data placeholder.");

        var head = Encoding.UTF8.GetBytes(template[..at]);
        var tail = Encoding.UTF8.GetBytes(template[(at + Placeholder.Length)..]);
        output.Write(head);
        JsonSerializer.Serialize(output, new
        {
            meta,
            imagesFolder = imagesFolderName,
            notes = result.Notes,
            warnings = result.Warnings,
            cacheFiles = result.CacheFiles,
            items = result.Items.Select(Dto),
        }, Json);
        output.Write(tail);
    }

    public static string Render(GalleryScanResult result, ReportMeta meta, string imagesFolderName = "thumbs")
    {
        using var ms = new MemoryStream();
        Write(ms, result, meta, imagesFolderName);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static string WriteFile(GalleryScanResult result, ReportMeta meta, string reportFolder, string imagesFolderName = "thumbs")
    {
        var path = Path.Combine(reportFolder, "Thumbnails.html");
        using var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        Write(fs, result, meta, imagesFolderName);
        return path;
    }

    /// <summary>Compact per-item shape for the page: images[0] is the best copy, no duplicated fields.</summary>
    static object Dto(GalleryItem i) => new
    {
        i.Id, i.Kind, i.Source, Evidence = i.Evidence.ToString(), i.User, i.CacheId, i.OriginalPath, i.Url,
        Status = i.Status.ToString(), FreeSpace = i.FoundInFreeSpace ? true : (bool?)null,
        Images = i.Images.Select(x => new { s = x.SizeClass, w = x.Width, h = x.Height, f = x.File, r = x.FoundInFreeSpace ? true : (bool?)null, rp = x.RestorePoint }),
        Dates = i.Dates is null ? null : new { after = i.Dates.After, before = i.Dates.Before, confidence = i.Dates.Confidence, sources = i.Dates.Sources },
        i.Note, Dup = i.DupGroup, i.RestorePoints, OnlyRestore = i.OnlyInRestorePoints ? true : (bool?)null,
    };

    static string LoadTemplate()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith("Templates.Thumbnails.html", StringComparison.Ordinal));
        using var reader = new StreamReader(asm.GetManifestResourceStream(name)!);
        return reader.ReadToEnd();
    }
}
