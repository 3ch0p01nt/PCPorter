namespace PCPorter.Collectors.Sources;

/// <param name="ProfilePath">Readable path here (mapped onto the source); null if unavailable.</param>
/// <param name="OriginalPath">The profile path as the scanned PC knows it (e.g. C:\Users\bob), for expanding %USERPROFILE% etc.</param>
public sealed record UserProfile(string Sid, string UserName, string? ProfilePath, string? Unavailable, string? OriginalPath = null);

/// <summary>A Windows installation to scan: this running PC, or another PC's drive. Read-only.</summary>
public interface ISystemSource : IDisposable
{
    bool IsLive { get; }
    /// <summary>Where files are read from: "C:\" live, "D:\" (or a device path) offline.</summary>
    string ReadRoot { get; }
    /// <summary>The scanned PC's own system drive, e.g. "C:".</summary>
    string OriginalSystemDrive { get; }
    /// <summary>Maps a path as the scanned PC knows it to a readable path here; null if it is on another volume.</summary>
    string? MapPath(string pathFromScannedPc);
    IRegKey? OpenHive(Hive hive, UserProfile? user = null);
    string? CurrentControlSet();
    IReadOnlyList<UserProfile> Users { get; }
    /// <summary>Notes about anything that could not be read (missing hives, dirty hives...).</summary>
    IReadOnlyList<string> Notes { get; }
}

/// <summary>Path rules shared by live and offline sources (pure, unit-tested).</summary>
public static class SourcePaths
{
    /// <summary>
    /// Expands %SystemDrive%/%SystemRoot%/%windir%/%ProgramData%/%ProgramFiles% etc. using the SCANNED PC's values,
    /// then maps its system drive onto <paramref name="readRoot"/>. Paths on other volumes return null.
    /// </summary>
    public static string? Map(string path, string originalSystemDrive, string readRoot, IReadOnlyDictionary<string, string>? env = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim();
        if (p.StartsWith('"'))
        {
            int close = p.IndexOf('"', 1);
            p = close > 0 ? p[1..close] : p[1..];          // quoted path followed by arguments: keep the path only
        }
        if (p.Contains('"')) return null;                   // not a single path
        p = Expand(p, originalSystemDrive, env).Replace('/', '\\');
        if ((p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal)) && p.Length > 6 && p[5] == ':') p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = originalSystemDrive + @"\Windows\" + p[@"\SystemRoot\".Length..];
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) p = originalSystemDrive + @"\Windows\" + p;
        if (p.Length < 3 || p[1] != ':' || p[2] != '\\') return null;
        if (!p.StartsWith(originalSystemDrive.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return null;
        var rest = Collapse(p[3..]);
        if (rest is null) return null;                      // ".." climbing above the drive
        var root = readRoot.EndsWith('\\') ? readRoot : readRoot + "\\";
        return root + rest;
    }

    /// <summary>Resolves "." and ".." segments; null if the path climbs above its root.</summary>
    static string? Collapse(string relative)
    {
        var parts = new List<string>();
        foreach (var seg in relative.Split('\\'))
        {
            if (seg is "" or ".") continue;
            if (seg == "..") { if (parts.Count == 0) return null; parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(seg);
        }
        return string.Join('\\', parts) + (relative.EndsWith('\\') && parts.Count > 0 ? "\\" : "");
    }

    /// <summary>Maps a path that may use per-user variables (%USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%, %HOMEPATH%).</summary>
    public static string? MapForUser(this ISystemSource source, string path, UserProfile user)
    {
        if (user.OriginalPath is not { } home) return source.MapPath(path);
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["USERPROFILE"] = home,
            ["APPDATA"] = home + @"\AppData\Roaming",
            ["LOCALAPPDATA"] = home + @"\AppData\Local",
            ["TEMP"] = home + @"\AppData\Local\Temp",
            ["TMP"] = home + @"\AppData\Local\Temp",
            ["HOMEDRIVE"] = home.Length >= 2 ? home[..2] : source.OriginalSystemDrive,
            ["HOMEPATH"] = home.Length > 2 ? home[2..] : "",
            ["USERNAME"] = user.UserName,
        };
        return Map(path, source.OriginalSystemDrive, source.ReadRoot, env);
    }

    public static string Expand(string path, string originalSystemDrive, IReadOnlyDictionary<string, string>? env = null)
    {
        var sysDrive = originalSystemDrive.TrimEnd('\\');
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemDrive"] = sysDrive,
            ["SystemRoot"] = sysDrive + @"\Windows",
            ["windir"] = sysDrive + @"\Windows",
            ["ProgramData"] = sysDrive + @"\ProgramData",
            ["ALLUSERSPROFILE"] = sysDrive + @"\ProgramData",
            ["ProgramFiles"] = sysDrive + @"\Program Files",
            ["ProgramW6432"] = sysDrive + @"\Program Files",
            ["ProgramFiles(x86)"] = sysDrive + @"\Program Files (x86)",
            ["CommonProgramFiles"] = sysDrive + @"\Program Files\Common Files",
            ["PUBLIC"] = sysDrive + @"\Users\Public",
        };
        if (env is not null) foreach (var (k, v) in env) vars[k] = v;
        var sb = new System.Text.StringBuilder();
        int i = 0;
        while (i < path.Length)
        {
            int start = path.IndexOf('%', i);
            int end = start < 0 ? -1 : path.IndexOf('%', start + 1);
            if (start < 0 || end < 0) { sb.Append(path, i, path.Length - i); break; }
            sb.Append(path, i, start - i);
            var name = path[(start + 1)..end];
            sb.Append(vars.TryGetValue(name, out var val) ? val : path[start..(end + 1)]);
            i = end + 1;
        }
        return sb.ToString();
    }

    /// <summary>Picks the current control set name from SYSTEM\Select (Current, then Default, then 001).</summary>
    public static string ControlSetName(IRegKey? systemRoot)
    {
        var select = systemRoot?.Open("Select");
        var n = select?.GetNumber("Current") ?? select?.GetNumber("Default") ?? 1;
        return $"ControlSet{n:D3}";
    }

    /// <summary>
    /// Users from SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList (real accounts only). When Windows has
    /// put a user on a temporary profile, the real one is the ".bak" twin, so that one is used; TEMP profiles are skipped.
    /// </summary>
    public static IReadOnlyList<UserProfile> Profiles(IRegKey? software, string originalSystemDrive, Func<string, string?> map)
    {
        var list = new List<UserProfile>();
        var profiles = software?.Open(@"Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (profiles is null) return list;
        var entries = profiles.SubKeys.ToDictionary(k => k.Name, k => k, StringComparer.OrdinalIgnoreCase);
        foreach (var (key, k) in entries)
        {
            if (key.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)) continue;
            if (!key.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !key.StartsWith("S-1-12-1-", StringComparison.Ordinal)) continue;
            var chosen = k;
            if (IsTemporary(k, originalSystemDrive) && entries.TryGetValue(key + ".bak", out var bak)) chosen = bak;
            if (IsTemporary(chosen, originalSystemDrive)) continue;
            var raw = chosen.GetString("ProfileImagePath");
            if (raw is null) continue;
            var expanded = Expand(raw, originalSystemDrive);
            var name = expanded.TrimEnd('\\').Split('\\').Last();
            var mapped = map(expanded);
            list.Add(new UserProfile(key, name, mapped, mapped is null ? "This profile is on another drive." : null, expanded));
        }
        return list;
    }

    /// <summary>Profile state bit 0x4 = temporary; folder names TEMP / TEMP.xxx are temporary too.</summary>
    static bool IsTemporary(IRegKey k, string sysDrive)
    {
        if (((k.GetNumber("State") ?? 0) & 0x4) != 0) return true;
        var folder = Expand(k.GetString("ProfileImagePath") ?? "", sysDrive).TrimEnd('\\').Split('\\').Last();
        return folder.Equals("TEMP", StringComparison.OrdinalIgnoreCase) || folder.StartsWith("TEMP.", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Opens and enumerates files strictly inside a source's read root. Inside <see cref="Confine"/>, every open and every
/// folder listing is checked against its REAL location, so a link on an old drive (e.g. "Documents and Settings" ->
/// C:\Users) can never lead into the files of the PC running PCPorter.
/// </summary>
public static class SourceFiles
{
    static readonly AsyncLocal<string?> ConfinedRoot = new();

    public static readonly EnumerationOptions Options = new()
    {
        IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false,
    };

    /// <summary>Confines file access in this async flow to <paramref name="readRoot"/> until disposed.</summary>
    public static IDisposable Confine(string readRoot)
    {
        var final = FileIdentity.FinalPath(readRoot) ?? readRoot;
        var previous = ConfinedRoot.Value;
        ConfinedRoot.Value = final.EndsWith('\\') ? final : final + "\\";
        return new Scope(() => ConfinedRoot.Value = previous);
    }

    static readonly AsyncLocal<Action<string, string>?> Observer = new();

    /// <summary>
    /// Reports every folder listing ("list") and file read ("read") in this async flow to <paramref name="onAccess"/>
    /// until disposed. The denylist regression test uses it to prove what a scan touches.
    /// </summary>
    public static IDisposable Observe(Action<string, string> onAccess)
    {
        var previous = Observer.Value;
        Observer.Value = onAccess;
        return new Scope(() => Observer.Value = previous);
    }

    /// <summary>True when the path's real location is inside the confined root (or no confinement is active).</summary>
    public static bool IsInside(string path)
    {
        var root = ConfinedRoot.Value;
        if (root is null) return true;
        var final = FileIdentity.FinalPath(path);
        if (final is null) return true;                     // does not exist: nothing to read anyway
        var f = final.EndsWith('\\') ? final : final + "\\";
        return f.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    public static IEnumerable<string> Files(string folder, string pattern = "*", bool recursive = false)
    {
        Observer.Value?.Invoke("list", folder);
        var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = recursive };
        try { return Directory.Exists(folder) && IsInside(folder) ? Directory.EnumerateFiles(folder, pattern, opts).ToList() : []; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    public static IEnumerable<string> Folders(string folder)
    {
        Observer.Value?.Invoke("list", folder);
        try { return Directory.Exists(folder) && IsInside(folder) ? Directory.EnumerateDirectories(folder, "*", Options).ToList() : []; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    public static FileStream OpenRead(string path)
    {
        Observer.Value?.Invoke("read", path);
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (ConfinedRoot.Value is { } root && FileIdentity.FinalPath(fs.SafeFileHandle) is { } final
            && !final.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            fs.Dispose();
            throw new UnauthorizedAccessException($"{path} leads outside the drive being scanned; it was not read.");
        }
        return fs;
    }

    /// <summary>Reads a whole (small) file from the scanned drive. Files over <paramref name="maxBytes"/> are refused.</summary>
    public static byte[] ReadAllBytes(string path, long maxBytes = 64L << 20)
    {
        using var fs = OpenRead(path);
        if (fs.Length > maxBytes) throw new IOException($"{Path.GetFileName(path)} is larger than expected ({fs.Length:N0} bytes); it was not read.");
        var bytes = new byte[fs.Length];
        fs.ReadExactly(bytes);
        return bytes;
    }

    sealed class Scope(Action onDispose) : IDisposable { public void Dispose() => onDispose(); }
}
