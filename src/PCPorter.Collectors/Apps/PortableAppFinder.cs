using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Apps;

/// <summary>
/// Programs started from Start Menu / Desktop shortcuts that no installer knows about ("portable" apps: copy the folder).
/// Shortcuts are parsed as binary files with the Lnk package; they are never resolved through the shell.
/// </summary>
public static class PortableAppFinder
{
    public sealed record Shortcut(string LnkPath, string Scope, string? Target);

    public static List<InstalledApp> Find(ISystemSource source, IReadOnlyList<InstalledApp> knownApps, IList<string> warnings)
    {
        var shortcuts = new List<Shortcut>();
        int unreadable = 0;
        void Scan(string? mappedFolder, string scope, bool recursive)
        {
            if (mappedFolder is null) return;
            foreach (var lnk in SourceFiles.Files(mappedFolder, "*.lnk", recursive))
            {
                var target = ReadTarget(lnk);
                if (target is null) { unreadable++; continue; }
                shortcuts.Add(new Shortcut(lnk, scope, target));
            }
        }

        Scan(source.MapPath(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs"), "Machine", true);
        Scan(source.MapPath(@"%PUBLIC%\Desktop"), "Machine", false);
        foreach (var u in source.Users)
        {
            if (u.ProfilePath is not { } profile) continue;
            Scan(Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"), "User:" + u.UserName, true);
            Scan(Path.Combine(profile, "Desktop"), "User:" + u.UserName, false);
        }
        if (unreadable > 0) warnings.Add($"{unreadable} shortcut(s) open Store apps or installer-managed programs (no plain file target) and were skipped.");
        return Classify(shortcuts, KnownFolders(source, knownApps));
    }

    /// <summary>Folders (scanned-PC paths) whose programs are already accounted for.</summary>
    public static List<string> KnownFolders(ISystemSource source, IEnumerable<InstalledApp> apps)
    {
        var d = source.OriginalSystemDrive;
        var folders = new List<string>
        {
            SourcePaths.Expand("%ProgramFiles%", d), SourcePaths.Expand("%ProgramFiles(x86)%", d), SourcePaths.Expand("%windir%", d),
        };
        // Each account's own "Program Files" (FOLDERID_UserProgramFiles): installers put per-user apps there
        // (Python, VS Code user setup...), even when their uninstall entry records no install folder.
        foreach (var u in source.Users)
            if (u.OriginalPath is { Length: > 3 } home) folders.Add(Path.Combine(home, "AppData", "Local", "Programs"));
        foreach (var a in apps)
        {
            if (a.InstallLocation is { Length: > 3 } loc) folders.Add(PathUtil.Clean(loc));
            if (PathUtil.ExeOf(a.UninstallString) is { } un && Path.GetDirectoryName(un) is { Length: > 3 } ud) folders.Add(ud);
        }
        return folders.Where(f => f.Length > 3).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static List<InstalledApp> Classify(IEnumerable<Shortcut> shortcuts, IReadOnlyList<string> knownFolders)
    {
        var result = new List<InstalledApp>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in shortcuts)
        {
            if (s.Target is not { } target) continue;
            if (!target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (target.Contains(@"\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase)) continue;   // Store app aliases
            if (knownFolders.Any(f => PathUtil.IsUnder(target, f))) continue;
            if (!seen.Add(target)) continue;
            var name = Path.GetFileNameWithoutExtension(s.LnkPath);
            result.Add(InstalledApp.Create(name, null, null, "neutral", s.Scope, AppKind.Portable, "lnk:" + target, Path.GetDirectoryName(target)));
        }
        return result;
    }

    /// <summary>Target path stored in the shortcut (as the scanned PC knows it), or null.</summary>
    public static string? ReadTarget(string lnkPath)
    {
        try
        {
            byte[] bytes;
            using (var fs = SourceFiles.OpenRead(lnkPath))
            {
                if (fs.Length is < 0x4C or > 1024 * 1024) return null;
                bytes = new byte[fs.Length];
                fs.ReadExactly(bytes);
            }
            var lnk = new Lnk.LnkFile(bytes, lnkPath, 1252);
            var local = lnk.LocalPath;
            if (string.IsNullOrWhiteSpace(local)) return null;
            var common = lnk.CommonPath;
            var full = string.IsNullOrEmpty(common) ? local : local.TrimEnd('\\') + "\\" + common.TrimStart('\\');
            return full.Length > 3 && full[1] == ':' ? full : null;
        }
        catch (Exception) { return null; }                                     // malformed shortcut: never fatal
    }
}
