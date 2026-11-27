using PCPorter.Core.Config;

namespace PCPorter.Core.Tests.Config;

public class SettingsStoreTests : IDisposable
{
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-test").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    [Fact] public void Missing_file_returns_defaults()
    {
        var s = new SettingsStore(_dir).Load();
        Assert.False(s.FirstRunCompleted);
        Assert.Equal(1, s.SchemaVersion);
    }

    [Fact] public void Save_then_load_round_trips()
    {
        var store = new SettingsStore(_dir);
        store.Save(new AppSettings { FirstRunCompleted = true, Theme = "Dark" });
        var s = store.Load();
        Assert.True(s.FirstRunCompleted);
        Assert.Equal("Dark", s.Theme);
        Assert.False(File.Exists(Path.Combine(_dir, "settings.json.tmp")));
    }

    [Fact] public void Corrupt_file_returns_defaults_and_keeps_backup()
    {
        File.WriteAllText(Path.Combine(_dir, "settings.json"), "{ not json");
        var s = new SettingsStore(_dir).Load();
        Assert.False(s.FirstRunCompleted);
        Assert.True(File.Exists(Path.Combine(_dir, "settings.json.corrupt")));
    }
}
