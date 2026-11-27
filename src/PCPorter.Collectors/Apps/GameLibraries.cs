using System.Text.Json;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Apps;

/// <summary>Games installed through Steam and the Epic Games Launcher (reinstalled through the launcher). Works live and offline.</summary>
public sealed class GameLibraries
{
    public List<InstalledApp> Games { get; } = [];
    /// <summary>Folders (scanned-PC paths) that hold games, used to classify registry entries as games.</summary>
    public List<string> LibraryFolders { get; } = [];

    const string SteamworksRedist = "228980";

    public static GameLibraries Read(ISystemSource source, IList<string> notes, IList<string> warnings)
    {
        var g = new GameLibraries();
        g.ReadSteam(source, notes, warnings);
        g.ReadEpic(source, warnings);
        return g;
    }

    // ---------------------------------------------------------------- Steam

    void ReadSteam(ISystemSource source, IList<string> notes, IList<string> warnings)
    {
        var roots = new List<string>();
        void AddRoot(string? p) { if (!string.IsNullOrWhiteSpace(p)) roots.Add(PathUtil.Clean(p)); }

        var sw = source.OpenHive(Hive.Software);
        AddRoot(sw?.Open(@"WOW6432Node\Valve\Steam")?.GetString("InstallPath"));
        AddRoot(sw?.Open(@"Valve\Steam")?.GetString("InstallPath"));
        foreach (var u in source.Users)
            AddRoot(source.OpenHive(Hive.NtUser, u)?.Open(@"Software\Valve\Steam")?.GetString("SteamPath"));
        AddRoot(SourcePaths.Expand(@"%ProgramFiles(x86)%\Steam", source.OriginalSystemDrive));

        var libraries = new List<string>();
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var mapped = source.MapPath(root);
            if (mapped is null || !Directory.Exists(mapped)) continue;
            AddLibrary(libraries, root);
            foreach (var vdfName in new[] { @"steamapps\libraryfolders.vdf", @"config\libraryfolders.vdf" })
            {
                var vdf = Path.Combine(mapped, vdfName);
                if (!File.Exists(vdf)) continue;
                try
                {
                    var lf = Vdf.Parse(ReadText(vdf));
                    var node = lf.Child("libraryfolders");
                    if (node is null) continue;
                    foreach (var child in node.Children.Values) if (child["path"] is { } p) AddLibrary(libraries, p);
                    foreach (var (k, v) in node.Values) if (int.TryParse(k, out _)) AddLibrary(libraries, v);   // old format
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { warnings.Add($"A Steam library list could not be read ({e.GetType().Name})."); }
            }
        }

        var seen = new HashSet<string>();
        int otherDrive = 0;
        foreach (var lib in libraries)
        {
            LibraryFolders.Add(lib + @"\steamapps");
            var mappedApps = source.MapPath(lib + @"\steamapps");
            if (mappedApps is null) { otherDrive++; continue; }
            foreach (var acf in SourceFiles.Files(mappedApps, "appmanifest_*.acf"))
            {
                try
                {
                    var state = Vdf.Parse(ReadText(acf)).Child("AppState");
                    var id = state?["appid"];
                    var name = state?["name"];
                    if (id is null || name is null || id == SteamworksRedist || !seen.Add(id)) continue;
                    var dir = state!["installdir"];
                    Games.Add(InstalledApp.Create(name, state["buildid"], null, "neutral", "Machine", AppKind.Game, "steam:" + id,
                        dir is null ? null : $@"{lib}\steamapps\common\{dir}",
                        state["LastUpdated"] is { } lu && long.TryParse(lu, out var t) && t > 0 ? DateOnly.FromDateTime(DateTimeOffset.FromUnixTimeSeconds(t).UtcDateTime) : null));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { warnings.Add($"A Steam game manifest could not be read ({e.GetType().Name})."); }
            }
        }
        if (otherDrive > 0) notes.Add($"{otherDrive} Steam game library folder(s) are on another drive and were not scanned.");
    }

    static void AddLibrary(List<string> libs, string path)
    {
        var p = PathUtil.Clean(path);
        if (p.Length >= 3 && !libs.Contains(p, StringComparer.OrdinalIgnoreCase)) libs.Add(p);
    }

    // ---------------------------------------------------------------- Epic

    void ReadEpic(ISystemSource source, IList<string> warnings)
    {
        var dir = source.MapPath(@"%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests");
        if (dir is null) return;
        foreach (var item in SourceFiles.Files(dir, "*.item"))
        {
            try
            {
                using var doc = JsonDocument.Parse(ReadText(item), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                var r = doc.RootElement;
                if (r.ValueKind != JsonValueKind.Object) continue;
                var name = Str(r, "DisplayName");
                if (name is null) continue;
                if (r.TryGetProperty("bIsIncompleteInstall", out var inc) && inc.ValueKind == JsonValueKind.True) continue;
                var loc = Str(r, "InstallLocation");
                if (loc is not null)
                {
                    loc = PathUtil.Clean(loc);
                    var parent = Path.GetDirectoryName(loc);
                    if (parent is { Length: > 3 } && !LibraryFolders.Contains(parent, StringComparer.OrdinalIgnoreCase)) LibraryFolders.Add(parent);
                }
                Games.Add(InstalledApp.Create(name, Str(r, "AppVersionString"), null, "neutral", "Machine", AppKind.Game,
                    "epic:" + (Str(r, "AppName") ?? Path.GetFileNameWithoutExtension(item)), loc));
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { warnings.Add($"An Epic Games manifest could not be read ({e.GetType().Name})."); }
        }
    }

    static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) ? v.GetString() : null;

    internal static string ReadText(string path)
    {
        using var fs = SourceFiles.OpenRead(path);
        if (fs.Length > 16 * 1024 * 1024) throw new IOException("File is too large.");
        using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: true);
        return sr.ReadToEnd();
    }
}
