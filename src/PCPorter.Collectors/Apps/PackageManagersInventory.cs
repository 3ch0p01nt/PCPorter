using System.Text.Json;
using System.Xml;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Apps;

public sealed record PackageManagerPackage(string Manager /*choco|scoop*/, string Id, string? Version, string? Title, string Scope, string? Bucket, string? Architecture);

/// <summary>Chocolatey and Scoop packages, read from their folders (works live and offline).</summary>
public static class PackageManagersInventory
{
    public static List<PackageManagerPackage> Read(ISystemSource source, IList<string> warnings)
    {
        var list = new List<PackageManagerPackage>();
        ReadChocolatey(source, list, warnings);
        foreach (var u in source.Users)
            if (u.ProfilePath is { } profile) ReadScoop(source, Path.Combine(profile, "scoop", "apps"), "User:" + u.UserName, list, warnings);
        if (source.MapPath(@"%ProgramData%\scoop\apps") is { } global) ReadScoop(source, global, "Machine", list, warnings);
        return list;
    }

    // ---------------------------------------------------------------- Chocolatey

    static void ReadChocolatey(ISystemSource source, List<PackageManagerPackage> list, IList<string> warnings)
    {
        var lib = source.MapPath(@"%ProgramData%\chocolatey\lib");
        if (lib is null) return;
        foreach (var pkgDir in SourceFiles.Folders(lib))
        {
            foreach (var nuspec in SourceFiles.Files(pkgDir, "*.nuspec"))
            {
                try
                {
                    var (id, version, title) = ParseNuspec(nuspec);
                    if (id is null || IsChocoHelper(id)) continue;
                    list.Add(new PackageManagerPackage("choco", id, version, title, "Machine", null, null));
                }
                catch (Exception e) when (e is XmlException or IOException or UnauthorizedAccessException) { warnings.Add($"A Chocolatey package file could not be read ({e.GetType().Name})."); }
                break;                                                     // one nuspec per package folder
            }
        }
    }

    static bool IsChocoHelper(string id) =>
        id.Equals("chocolatey", StringComparison.OrdinalIgnoreCase) || id.StartsWith("chocolatey-", StringComparison.OrdinalIgnoreCase)
        || id.EndsWith(".extension", StringComparison.OrdinalIgnoreCase);

    public static (string? Id, string? Version, string? Title) ParseNuspec(string path)
    {
        using var fs = SourceFiles.OpenRead(path);
        using var xr = XmlReader.Create(fs, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true });
        string? id = null, version = null, title = null;
        bool inMetadata = false;
        xr.Read();
        while (!xr.EOF)
        {
            if (xr.NodeType == XmlNodeType.Element && xr.LocalName == "metadata") inMetadata = true;
            else if (xr.NodeType == XmlNodeType.EndElement && xr.LocalName == "metadata") break;
            else if (inMetadata && xr.NodeType == XmlNodeType.Element && xr.Depth == 2 && xr.LocalName is "id" or "version" or "title")
            {
                var which = xr.LocalName;
                if (xr.IsEmptyElement) { xr.Read(); continue; }
                var text = xr.ReadElementContentAsString().Trim();               // already moves to the next node
                if (which == "id") id = text; else if (which == "version") version = text; else title = text;
                continue;
            }
            xr.Read();
        }
        return (string.IsNullOrEmpty(id) ? null : id, string.IsNullOrEmpty(version) ? null : version, string.IsNullOrEmpty(title) ? null : title);
    }

    // ---------------------------------------------------------------- Scoop

    static void ReadScoop(ISystemSource source, string appsDir, string scope, List<PackageManagerPackage> list, IList<string> warnings)
    {
        foreach (var appDir in SourceFiles.Folders(appsDir))
        {
            var name = Path.GetFileName(appDir);
            if (name.Equals("scoop", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var current = CurrentFolder(source, appDir);
                if (current is null) continue;
                var manifest = Path.Combine(current, "manifest.json");
                if (!File.Exists(manifest)) continue;
                string? version, bucket = null, arch = null;
                using (var doc = JsonDocument.Parse(GameLibraries.ReadText(manifest), JsonOpts))
                    version = Str(doc.RootElement, "version");
                var install = Path.Combine(current, "install.json");
                if (File.Exists(install))
                {
                    using var doc = JsonDocument.Parse(GameLibraries.ReadText(install), JsonOpts);
                    bucket = Str(doc.RootElement, "bucket");
                    arch = Str(doc.RootElement, "architecture") switch { "64bit" => "x64", "32bit" => "x86", "arm64" => "arm64", _ => null };
                }
                list.Add(new PackageManagerPackage("scoop", name, version, null, scope, bucket, arch));
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { warnings.Add($"A Scoop app manifest could not be read ({e.GetType().Name})."); }
        }
    }

    /// <summary>
    /// Scoop's "current" is a junction. Its target is a path on the scanned PC, so it is mapped (offline it must not be
    /// followed onto this PC's drive). If the target cannot be mapped, the newest real version folder is used.
    /// </summary>
    static string? CurrentFolder(ISystemSource source, string appDir)
    {
        var current = new DirectoryInfo(Path.Combine(appDir, "current"));
        if (current.Exists && !current.Attributes.HasFlag(FileAttributes.ReparsePoint)) return current.FullName;
        if (current.Exists && current.LinkTarget is { } target && source.MapPath(target) is { } mapped
            && Directory.Exists(mapped) && !new DirectoryInfo(mapped).Attributes.HasFlag(FileAttributes.ReparsePoint))
            return mapped;
        return SourceFiles.Folders(appDir)
            .Where(d => !Path.GetFileName(d).Equals("current", StringComparison.OrdinalIgnoreCase) && File.Exists(Path.Combine(d, "manifest.json")))
            .OrderByDescending(d => Directory.GetLastWriteTimeUtc(d))
            .FirstOrDefault();
    }

    static readonly JsonDocumentOptions JsonOpts = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) ? v.GetString() : null;

    /// <summary>Attaches each package to a matching registry app (ChocoId/ScoopId) or adds it as its own app.</summary>
    public static void Merge(List<InstalledApp> apps, IEnumerable<PackageManagerPackage> packages)
    {
        foreach (var p in packages)
        {
            var baseId = p.Id;
            foreach (var suffix in new[] { ".install", ".portable" })
                if (baseId.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) baseId = baseId[..^suffix.Length];
            var keys = new HashSet<string> { AppNameNormalizer.MatchKey(baseId) };
            if (p.Title is not null) keys.Add(AppNameNormalizer.MatchKey(p.Title));
            keys.Remove("");

            int idx = apps.FindIndex(a => !a.Hidden && a.Kind is AppKind.Win32 or AppKind.Portable
                && (p.Manager == "choco" ? a.ChocoId is null : a.ScoopId is null)
                && keys.Contains(AppNameNormalizer.MatchKey(a.Name)));
            if (idx >= 0)
            {
                apps[idx] = p.Manager == "choco" ? apps[idx] with { ChocoId = p.Id } : apps[idx] with { ScoopId = p.Id };
                continue;
            }
            var source = p.Bucket is null ? $"{p.Manager}:{p.Id}" : $"{p.Manager}:{p.Bucket}/{p.Id}";
            var app = InstalledApp.Create(p.Title ?? p.Id, p.Version, null, p.Architecture ?? "neutral", p.Scope, AppKind.Win32, source);
            apps.Add(p.Manager == "choco" ? app with { ChocoId = p.Id } : app with { ScoopId = p.Id });
        }
    }
}
