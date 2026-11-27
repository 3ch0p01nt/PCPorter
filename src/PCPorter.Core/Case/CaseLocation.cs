namespace PCPorter.Core.Case;

public sealed record CaseLocationResult(bool IsAllowed, string? Reason);

/// <summary>
/// Case files hold browsing history, images and passwords: never let them land in a cloud-synced folder.
/// v1 checks OneDrive environment roots and common sync-folder names; v2 (Phase 2 Task 2) adds
/// real-path resolution, sync-root APIs and network/UNC rejection.
/// </summary>
public static class CaseLocation
{
    static readonly string[] EnvRoots = ["OneDrive", "OneDriveCommercial", "OneDriveConsumer"];
    static readonly string[] SyncedFolderNames = ["Dropbox", "Google Drive", "iCloudDrive", "Box"];

    public static CaseLocationResult Check(string path, Func<string, string?>? getEnv = null)
    {
        getEnv ??= Environment.GetEnvironmentVariable;
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
            return new(false, "Network folders are not allowed. Pick the backup drive or a local folder.");

        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        foreach (var name in EnvRoots)
            if (getEnv(name) is { Length: > 0 } root && IsUnder(full, root))
                return new(false, $"This folder is synced by OneDrive ({root}). Pick the backup drive or a local folder.");

        foreach (var part in full.Split(Path.DirectorySeparatorChar))
        {
            // Environment variables belong to whoever elevated, so also catch OneDrive folders by name.
            if (part.Equals("OneDrive", StringComparison.OrdinalIgnoreCase) || part.StartsWith("OneDrive - ", StringComparison.OrdinalIgnoreCase))
                return new(false, $"This folder looks synced by OneDrive ({part}). Pick the backup drive or a local folder.");
            foreach (var synced in SyncedFolderNames)
                if (part.Equals(synced, StringComparison.OrdinalIgnoreCase)
                    || part.StartsWith(synced + " (", StringComparison.OrdinalIgnoreCase))
                    return new(false, $"This folder looks cloud-synced ({part}). Pick the backup drive or a local folder.");
        }

        return new(true, null);
    }

    static bool IsUnder(string path, string root)
    {
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return path.Equals(root, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
