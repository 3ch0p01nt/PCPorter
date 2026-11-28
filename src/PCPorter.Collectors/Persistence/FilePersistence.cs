using System.Text;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

/// <summary>
/// File-based autostart locations (plan Task 7c): Startup folders, PowerShell profiles, Office startup folders, the
/// accessibility tools, and (live only) WMI event subscriptions. Shortcuts are parsed as binary with the Lnk package;
/// they are never resolved through the shell.
/// </summary>
public static class FilePersistence
{
    const string StartupApproved = @"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
    static readonly string[] TextScripts = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".vbe", ".jse", ".wsf", ".hta"];
    const int MaxScriptChars = 64 * 1024;
    const string ShellFolders = @"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

    static bool IsOtherFolder(string? moved, string? standard) =>
        moved is not null && !string.Equals(Path.TrimEndingDirectorySeparator(moved), Path.TrimEndingDirectorySeparator(standard ?? ""), StringComparison.OrdinalIgnoreCase);

    static FilePersistence()
    {
        try { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); } catch (ArgumentException) { }
    }

    public static IReadOnlyList<PersistenceEntry> Read(ISystemSource source, IWmiClient? wmi, IList<string> warnings, CancellationToken ct = default)
    {
        var list = new List<PersistenceEntry>();
        void Do(string what, Action a)
        {
            ct.ThrowIfCancellationRequested();
            try { a(); }
            catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"Could not read {what}: {e.Message}"); }
        }

        IRegKey? software = null;
        Do("the SOFTWARE hive", () => software = source.OpenHive(Hive.Software));

        Do("the accessibility tools", () => Accessibility(list, source));
        var commonStartup = source.MapPath(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup");
        Do("the all-users Startup folder", () => StartupFolder(list, source, commonStartup, "Startup folder (all users)", software?.Open(StartupApproved), null, warnings));
        Do("a moved all-users Startup folder", () =>
        {
            var moved = software?.Open(ShellFolders)?.GetString("Common Startup") is { Length: > 0 } v ? source.MapPath(v) : null;
            if (IsOtherFolder(moved, commonStartup))
                StartupFolder(list, source, moved, "Startup folder (all users, moved)", software?.Open(StartupApproved), null, warnings);
        });
        Do("the system PowerShell profiles", () =>
        {
            foreach (var dir in new[] { @"%SystemRoot%\System32\WindowsPowerShell\v1.0", @"%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0" })
                Listed(list, source, source.MapPath(dir), "*profile.ps1", "PowerShell profile (all users)", null);
            if (source.MapPath(@"%ProgramFiles%\PowerShell") is { } pwsh)
                foreach (var v in SourceFiles.Folders(pwsh))
                    Listed(list, source, v, "*profile.ps1", "PowerShell 7 profile (all users)", null);
        });

        IReadOnlyList<UserProfile> users = [];
        Do("the user list", () => users = source.Users);
        foreach (var user in users)
        {
            if (user.ProfilePath is not { } home || user.Unavailable is not null) continue;
            var who = user.UserName;
            Do($"the Startup folder of {who}", () =>
            {
                IRegKey? approved = null;
                try { approved = source.OpenHive(Hive.NtUser, user)?.Open(@"Software\" + StartupApproved); }
                catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"StartupApproved of {who} could not be read: {e.Message}"); }
                var standard = Path.Combine(home, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
                StartupFolder(list, source, standard, $"Startup folder ({who})", approved, user, warnings);
                // Explorer starts whatever folder "User Shell Folders\Startup" names, so a redirected folder is checked too.
                IRegKey? shell = null;
                try { shell = source.OpenHive(Hive.NtUser, user)?.Open(@"Software\" + ShellFolders); }
                catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"The folder settings of {who} could not be read: {e.Message}"); }
                var moved = shell?.GetString("Startup") is { Length: > 0 } v ? source.MapForUser(v, user) : null;
                if (IsOtherFolder(moved, standard))
                    StartupFolder(list, source, moved, $"Startup folder ({who}, moved)", approved, user, warnings);
            });
            Do($"the PowerShell profiles of {who}", () =>
            {
                foreach (var docs in DocumentsFolders(home))
                {
                    Listed(list, source, Path.Combine(docs, "WindowsPowerShell"), "*profile.ps1", $"PowerShell profile ({who})", user);
                    Listed(list, source, Path.Combine(docs, "PowerShell"), "*.ps1", $"PowerShell 7 profile ({who})", user);
                }
            });
            Do($"the Office startup folders of {who}", () =>
            {
                Listed(list, source, Path.Combine(home, @"AppData\Roaming\Microsoft\Word\STARTUP"), "*", $"Word startup folder ({who})", user);
                Listed(list, source, Path.Combine(home, @"AppData\Roaming\Microsoft\Excel\XLSTART"), "*", $"Excel startup folder ({who})", user);
            });
        }

        if (source.IsLive && wmi is not null) Do("WMI event subscriptions", () => Wmi(list, wmi, warnings));
        return list;
    }

    static IEnumerable<string> DocumentsFolders(string home)
    {
        yield return Path.Combine(home, "Documents");
        foreach (var od in SourceFiles.Folders(home).Where(d => Path.GetFileName(d).StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase)))
            yield return Path.Combine(od, "Documents");
    }

    static void Accessibility(List<PersistenceEntry> list, ISystemSource source)
    {
        foreach (var tool in PersistenceRules.AccessibilityTools)
        {
            var scanned = @"%SystemRoot%\System32\" + tool;
            var mapped = source.MapPath(scanned);
            if (mapped is null || !SourcePresence.IsFile(mapped)) continue;
            list.Add(new PersistenceEntry("Accessibility tools", tool, scanned, EntryKind.Accessibility) { LastWrite = LastWrite(mapped) });
        }
    }

    static DateTimeOffset? LastWrite(string path)
    {
        try { return new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    static void StartupFolder(List<PersistenceEntry> list, ISystemSource source, string? dir, string location, IRegKey? approved, UserProfile? user, IList<string> warnings)
    {
        if (dir is null) return;
        foreach (var file in SourceFiles.Files(dir))
        {
            var name = Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            var disabled = RegistryPersistence.IsDisabledByStartupApproved(approved, name);
            var scanned = PersistencePaths.ToScanned(source, file);
            if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var (target, args, relative) = ReadShortcut(file, warnings);
                if (target is not null && relative) target = PersistencePaths.ToScanned(source, target);
                if (target is null)
                {
                    list.Add(new PersistenceEntry(location, name, scanned) { Disabled = disabled, LastWrite = LastWrite(file), User = user, NoFile = true,
                        Note = "The shortcut's target could not be read." });
                    continue;
                }
                var cmd = Quote(target) + (string.IsNullOrWhiteSpace(args) ? "" : " " + args.Trim());
                list.Add(new PersistenceEntry(location, name, cmd, EntryKind.File) { Disabled = disabled, LastWrite = LastWrite(file), User = user });
                continue;
            }
            list.Add(new PersistenceEntry(location, name, Quote(scanned), EntryKind.File)
            {
                Payload = scanned, Disabled = disabled, LastWrite = LastWrite(file), User = user, ScriptText = ScriptText(file),
            });
        }
    }

    /// <summary>Lists files in a folder as entries whose payload is the file itself.</summary>
    static void Listed(List<PersistenceEntry> list, ISystemSource source, string? dir, string pattern, string location, UserProfile? user)
    {
        if (dir is null) return;
        foreach (var file in SourceFiles.Files(dir, pattern))
        {
            var scanned = PersistencePaths.ToScanned(source, file);
            list.Add(new PersistenceEntry(location, Path.GetFileName(file), Quote(scanned), EntryKind.File)
            {
                Payload = scanned, LastWrite = LastWrite(file), User = user, ScriptText = ScriptText(file),
            });
        }
    }

    static string Quote(string path) => path.Contains(' ') && !path.StartsWith('"') ? "\"" + path + "\"" : path;

    static string? ScriptText(string file)
    {
        if (!TextScripts.Any(x => file.EndsWith(x, StringComparison.OrdinalIgnoreCase))) return null;
        try
        {
            using var fs = SourceFiles.OpenRead(file);
            using var r = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var buf = new char[MaxScriptChars];
            var n = r.ReadBlock(buf, 0, buf.Length);
            return new string(buf, 0, n);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Binary .lnk parse (Lnk package). Never IShellLink::Resolve, which can touch the network and update the file.</summary>
    public static (string? Target, string? Arguments, bool FromRelativePath) ReadShortcut(string lnkPath, IList<string>? warnings = null)
    {
        try
        {
            // Read through SourceFiles so the confinement to the scanned drive applies (the package would open the path itself).
            var lnk = new Lnk.LnkFile(PCPorter.Collectors.Sources.SourceFiles.ReadAllBytes(lnkPath), lnkPath, 1252);
            string? target = lnk.LocalPath;
            bool relative = false;
            if (string.IsNullOrWhiteSpace(target) && !string.IsNullOrWhiteSpace(lnk.CommonPath)) target = lnk.CommonPath;
            if (string.IsNullOrWhiteSpace(target) && !string.IsNullOrWhiteSpace(lnk.RelativePath))
            {
                var baseDir = Path.GetDirectoryName(lnkPath) ?? "";
                target = Path.GetFullPath(Path.Combine(baseDir, lnk.RelativePath));
                relative = true;
            }
            return (string.IsNullOrWhiteSpace(target) ? null : target, lnk.Arguments, relative);
        }
        catch (Exception e)
        {
            warnings?.Add($"A shortcut could not be read ({Path.GetFileName(lnkPath)}): {e.Message}");
            return (null, null, false);
        }
    }

    static void Wmi(List<PersistenceEntry> list, IWmiClient wmi, IList<string> warnings)
    {
        const string ns = @"root\subscription";
        var bindings = wmi.Query(ns, "SELECT Filter, Consumer FROM __FilterToConsumerBinding");
        if (bindings.Outcome != WmiOutcome.Ok)
        {
            warnings.Add($"WMI event subscriptions could not be read ({bindings.Outcome}).");
            return;
        }
        var bound = bindings.Rows.Select(r => r.TryGetValue("Consumer", out var c) ? c?.ToString() ?? "" : "").ToList();
        bool IsBound(string cls, string name) => bound.Any(b => b.Contains(cls, StringComparison.OrdinalIgnoreCase)
            && b.Contains("\"" + name + "\"", StringComparison.OrdinalIgnoreCase));
        static string Get(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) ? v?.ToString() ?? "" : "";

        var cl = wmi.Query(ns, "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer");
        if (cl.Outcome == WmiOutcome.Ok)
            foreach (var r in cl.Rows)
            {
                var name = Get(r, "Name");
                if (!IsBound("CommandLineEventConsumer", name)) continue;
                var cmd = Get(r, "CommandLineTemplate");
                if (cmd.Length == 0) cmd = Get(r, "ExecutablePath");
                list.Add(new PersistenceEntry(@"WMI root\subscription CommandLineEventConsumer", name, cmd, EntryKind.WmiConsumer));
            }
        else warnings.Add($"WMI command-line consumers could not be read ({cl.Outcome}).");

        var sc = wmi.Query(ns, "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer");
        if (sc.Outcome == WmiOutcome.Ok)
            foreach (var r in sc.Rows)
            {
                var name = Get(r, "Name");
                if (!IsBound("ActiveScriptEventConsumer", name)) continue;
                var file = Get(r, "ScriptFileName");
                var text = Get(r, "ScriptText");
                list.Add(new PersistenceEntry(@"WMI root\subscription ActiveScriptEventConsumer", name, file.Length > 0 ? file : $"{Get(r, "ScriptingEngine")} script", EntryKind.WmiConsumer)
                {
                    ScriptText = text.Length > MaxScriptChars ? text[..MaxScriptChars] : text, NoFile = file.Length == 0,
                });
            }
        else warnings.Add($"WMI script consumers could not be read ({sc.Outcome}).");
    }
}
