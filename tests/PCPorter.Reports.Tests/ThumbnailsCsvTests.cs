using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

/// <summary>
/// Thumbnails.html does not load report-kit.js, so it carries its own copy of the kit's CSV escaping (formula
/// defusing: a leading = + - @ tab or CR, or whitespace before one). The two copies must stay identical.
/// </summary>
public class ThumbnailsCsvTests
{
    static string Resource(string suffix)
    {
        var asm = typeof(GalleryReport).Assembly;
        using var reader = new StreamReader(asm.GetManifestResourceStream(asm.GetManifestResourceNames().Single(n => n.EndsWith(suffix, StringComparison.Ordinal)))!);
        return reader.ReadToEnd();
    }

    /// <summary>The lines of "function csvEscape(v) { ... }", trimmed, up to the closing brace at the function's own indent.</summary>
    static List<string> CsvEscape(string source)
    {
        var lines = source.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var start = lines.FindIndex(l => l.TrimStart().StartsWith("function csvEscape(v) {", StringComparison.Ordinal));
        Assert.True(start >= 0, "no csvEscape function");
        var indent = lines[start].Length - lines[start].TrimStart().Length;
        var end = lines.FindIndex(start + 1, l => l.Trim() == "}" && l.Length - l.TrimStart().Length == indent);
        Assert.True(end > start, "csvEscape has no closing brace");
        return lines[start..(end + 1)].Select(l => l.Trim()).ToList();
    }

    [Fact]
    public void The_gallery_csv_uses_the_kits_escaping()
    {
        var kit = CsvEscape(Resource("Templates.report-kit.js"));
        Assert.Contains(kit, l => l.Contains(@"\s+[=+\-@]", StringComparison.Ordinal));     // the stricter rules are the kit's
        Assert.Equal(kit, CsvEscape(Resource("Templates.Thumbnails.html")));
    }

    [Fact]
    public void The_gallery_export_escapes_every_cell_with_it()
    {
        var html = Resource("Templates.Thumbnails.html");
        Assert.Contains(".map(csvEscape).join(\",\")", html);
        Assert.DoesNotContain("const esc = ", html);
    }
}
