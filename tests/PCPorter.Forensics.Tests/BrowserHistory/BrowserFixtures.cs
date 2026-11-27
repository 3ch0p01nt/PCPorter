using System.Text;

namespace PCPorter.Forensics.Tests.BrowserHistory;

/// <summary>Synthetic browser profile trees for the history tests. Nothing here comes from a real PC.</summary>
internal static class BrowserFixtures
{
    public static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "pcporter-history-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Delete(string dir)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Creates a file (and its folders) with some bytes.</summary>
    public static string Touch(string root, string relative, string content = "x")
    {
        var path = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, Encoding.UTF8);
        return path;
    }

    /// <summary>Chromium "Local State" with display names for the given profile folders.</summary>
    public static string LocalState(params (string Dir, string Name)[] profiles)
    {
        var cache = string.Join(",", profiles.Select(p => $"\"{p.Dir}\":{{\"name\":\"{p.Name}\",\"avatar_icon\":\"x\"}}"));
        return "{\"os_crypt\":{\"encrypted_key\":\"not-a-real-key\"},\"profile\":{\"info_cache\":{" + cache + "}}}";
    }

    public static long WebKit(DateTimeOffset t) => t.UtcDateTime.ToFileTimeUtc() / 10;
}
