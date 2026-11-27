using System.Text.Json;

namespace PCPorter.Core.Config;

public sealed class SettingsStore(string directory)
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    string FilePath => Path.Combine(directory, "settings.json");

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCPorter");

    public AppSettings Load()
    {
        if (!File.Exists(FilePath)) return new AppSettings();
        try { return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Json) ?? new AppSettings(); }
        catch (JsonException)
        {
            File.Copy(FilePath, FilePath + ".corrupt", overwrite: true);
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(directory);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Json));
        File.Move(tmp, FilePath, overwrite: true);   // atomic replace: a crash never leaves half a file
    }
}
