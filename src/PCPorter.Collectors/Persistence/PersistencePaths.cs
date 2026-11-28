using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

/// <summary>Path helpers shared by the persistence readers.</summary>
public static class PersistencePaths
{
    /// <summary>Turns a readable path here (D:\Users\bob\x) back into the path the scanned PC knows (C:\Users\bob\x).</summary>
    public static string ToScanned(ISystemSource source, string readPath)
    {
        var root = source.ReadRoot.EndsWith('\\') ? source.ReadRoot : source.ReadRoot + "\\";
        return readPath.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            ? source.OriginalSystemDrive.TrimEnd('\\') + "\\" + readPath[root.Length..]
            : readPath;
    }

    /// <summary>The user's own environment (as the scanned PC would expand it) for %APPDATA%, %TEMP% and friends.</summary>
    public static IReadOnlyDictionary<string, string>? UserEnv(ISystemSource source, UserProfile? user)
    {
        if (user?.ProfilePath is not { } profile) return null;
        var home = ToScanned(source, profile).TrimEnd('\\');
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["USERPROFILE"] = home,
            ["HOMEPATH"] = home.Length > 2 ? home[2..] : home,
            ["APPDATA"] = home + @"\AppData\Roaming",
            ["LOCALAPPDATA"] = home + @"\AppData\Local",
            ["TEMP"] = home + @"\AppData\Local\Temp",
            ["TMP"] = home + @"\AppData\Local\Temp",
            ["USERNAME"] = user.UserName,
        };
    }

    /// <summary>Expands with the user's environment and maps onto the read root. Null when not on the scanned system volume.</summary>
    public static string? MapFile(ISystemSource source, string scannedPath, UserProfile? user)
    {
        try { return source.MapPath(SourcePaths.Expand(scannedPath, source.OriginalSystemDrive, UserEnv(source, user))); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or IOException) { return null; }
    }

    /// <summary>
    /// For splitting a command line into program and arguments: true when the file exists. A path behind a link is
    /// not followed (it may point at a network share): false, so the split falls back to the executable-extension
    /// rule; whether the file is missing is decided by the signature check, which calls it "not checked".
    /// </summary>
    public static bool FileExists(ISystemSource source, string scannedPath, UserProfile? user) =>
        MapFile(source, scannedPath, user) is { } mapped && SourcePresence.IsFile(mapped);

    /// <summary>Plain name for a user hive in locations: HKCU(bob).</summary>
    public static string UserLabel(UserProfile user) => $"HKCU({user.UserName})";
}
