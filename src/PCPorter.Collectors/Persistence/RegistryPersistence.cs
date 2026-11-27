using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

/// <summary>
/// Autostart locations in the registry (plan Task 7b). Read-only. Only the named values are read; in particular the
/// Winlogon key is never enumerated, so DefaultPassword is never read.
/// </summary>
public static class RegistryPersistence
{
    const string CV = @"Microsoft\Windows\CurrentVersion";
    const string NT = @"Microsoft\Windows NT\CurrentVersion";
    const string Hklm = @"HKLM\SOFTWARE";
    const string HklmSys = @"HKLM\SYSTEM\CurrentControlSet";
    static readonly string[] RunKeys = ["Run", "RunOnce", "RunServices", "RunServicesOnce", @"Policies\Explorer\Run"];
    static readonly string[] LsaLists = ["Authentication Packages", "Security Packages", "Notification Packages"];
    static readonly (string Browser, string Path)[] BrowserPolicyRoots =
    [
        ("Google Chrome", @"Policies\Google\Chrome"),
        ("Microsoft Edge", @"Policies\Microsoft\Edge"),
        ("Chromium", @"Policies\Chromium"),
        ("Brave", @"Policies\BraveSoftware\Brave"),
    ];
    /// <summary>Extensions that installed programs register outside the web store (a classic adware route).</summary>
    static readonly (string Browser, string Path)[] ExternalExtensionRoots =
    [
        ("Google Chrome", @"Google\Chrome\Extensions"),
        ("Microsoft Edge", @"Microsoft\Edge\Extensions"),
    ];
    /// <summary>File types whose "open" command malware replaces (every program start, or a UAC bypass via ms-settings / mscfile).</summary>
    static readonly string[] HijackableClasses = ["exefile", "comfile", "batfile", "cmdfile", "piffile", "ms-settings", "mscfile"];

    public static IReadOnlyList<PersistenceEntry> Read(ISystemSource source, IList<string> warnings, CancellationToken ct = default)
    {
        var list = new List<PersistenceEntry>();
        void Do(string what, Action a)
        {
            ct.ThrowIfCancellationRequested();
            try { a(); }
            catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"Could not read {what}: {e.Message}"); }
        }

        IRegKey? software = null, system = null;
        Do("the SOFTWARE hive", () => software = source.OpenHive(Hive.Software));
        Do("the SYSTEM hive", () => system = source.OpenHive(Hive.System));
        if (software is null) warnings.Add("The SOFTWARE hive could not be opened; machine-wide startup entries were skipped.");

        if (software is { } sw)
        {
            var approved = sw.Open(CV + @"\Explorer\StartupApproved");
            var wow = sw.Open("WOW6432Node");
            Do("Run keys", () => RunFamily(list, sw, Hklm, approved, "Run", null));
            if (wow is not null) Do("32-bit Run keys", () => RunFamily(list, wow, Hklm + @"\WOW6432Node", approved, "Run32", null));
            Do("Winlogon", () => Winlogon(list, sw, Hklm));
            Do("AppInit_DLLs", () => AppInit(list, sw, Hklm));
            if (wow is not null) Do("32-bit AppInit_DLLs", () => AppInit(list, wow, Hklm + @"\WOW6432Node"));
            Do("Image File Execution Options", () => Ifeo(list, sw, Hklm));
            if (wow is not null) Do("32-bit Image File Execution Options", () => Ifeo(list, wow, Hklm + @"\WOW6432Node"));
            Do("Active Setup", () => ActiveSetup(list, sw, Hklm));
            if (wow is not null) Do("32-bit Active Setup", () => ActiveSetup(list, wow, Hklm + @"\WOW6432Node"));
            Do("Netsh helpers", () => Netsh(list, sw, Hklm));
            if (wow is not null) Do("32-bit Netsh helpers", () => Netsh(list, wow, Hklm + @"\WOW6432Node"));
            Do("browser extension policies", () => BrowserPolicies(list, sw, Hklm, null));
            Do("browser extensions added by programs", () => ExternalExtensions(list, sw, Hklm, null));
            if (wow is not null) Do("32-bit browser extensions added by programs", () => ExternalExtensions(list, wow, Hklm + @"\WOW6432Node", null));
            Do("the Command Processor AutoRun", () => CmdAutoRun(list, sw, Hklm, null));
            if (wow is not null) Do("the 32-bit Command Processor AutoRun", () => CmdAutoRun(list, wow, Hklm + @"\WOW6432Node", null));
            Do("file type open commands", () => MachineFileTypes(list, sw.Open("Classes"), Hklm + @"\Classes"));
        }

        string? ccsName = null;
        Do("the current control set", () => ccsName = source.CurrentControlSet());
        if (system?.Open(ccsName ?? "ControlSet001") is { } ccs)
        {
            Do("services", () => Services(list, ccs));
            Do("BootExecute", () => BootExecute(list, ccs));
            Do("LSA packages", () => Lsa(list, ccs));
            Do("AppCertDlls", () => AppCertDlls(list, ccs));
            Do("print monitors", () => PrintMonitors(list, ccs));
        }
        else if (system is not null) warnings.Add("The current control set could not be found; services were skipped.");

        IReadOnlyList<UserProfile> users = [];
        Do("the user list", () => users = source.Users);
        var machineClsid = new[] { software?.Open(@"Classes\CLSID"), software?.Open(@"WOW6432Node\Classes\CLSID") };
        foreach (var user in users)
        {
            if (user.Unavailable is not null) continue;
            IRegKey? nt = null, cls = null;
            Do($"the registry of {user.UserName}", () => nt = source.OpenHive(Hive.NtUser, user));
            Do($"the classes registry of {user.UserName}", () => cls = source.OpenHive(Hive.UsrClass, user));
            var label = PersistencePaths.UserLabel(user);
            if (nt is not null) Do($"screen saver of {user.UserName}", () => ScreenSaver(list, nt, label, user));
            if (nt is null) { warnings.Add($"The registry of {user.UserName} could not be read; their startup entries were skipped."); }
            else if (nt.Open("Software") is { } usw)
            {
                var approved = usw.Open(CV + @"\Explorer\StartupApproved");
                Do($"Run keys of {user.UserName}", () => RunFamily(list, usw, label + @"\Software", approved, "Run", user));
                if (usw.Open("WOW6432Node") is { } uwow)
                    Do($"32-bit Run keys of {user.UserName}", () => RunFamily(list, uwow, label + @"\Software\WOW6432Node", approved, "Run32", user));
                Do($"Winlogon of {user.UserName}", () => UserWinlogon(list, usw, label + @"\Software", user));
                Do($"browser extension policies of {user.UserName}", () => BrowserPolicies(list, usw, label + @"\Software", user));
                Do($"browser extensions added by programs for {user.UserName}", () => ExternalExtensions(list, usw, label + @"\Software", user));
                Do($"the Command Processor AutoRun of {user.UserName}", () => CmdAutoRun(list, usw, label + @"\Software", user));
                Do($"the Load and Run values of {user.UserName}", () => WindowsLoadRun(list, usw, label + @"\Software", user));
                Do($"COM registrations of {user.UserName}", () => ComHijack(list, usw.Open(@"Classes\CLSID"), cls?.Open("CLSID"), machineClsid, label, user));
            }
            else if (cls is not null)
                Do($"COM registrations of {user.UserName}", () => ComHijack(list, null, cls.Open("CLSID"), machineClsid, label, user));
            if (nt is not null) Do($"the logon script of {user.UserName}", () => LogonScript(list, nt, label, user));
            Do($"file type open commands of {user.UserName}", () => UserFileTypes(list, nt?.Open(@"Software\Classes"), cls, label, user));
        }
        return list;
    }

    static string ValueLabel(string name) => name.Length == 0 ? "(Default)" : name.Replace("\0", "\\0");

    /// <summary>StartupApproved: first byte odd = turned off in Settings / Task Manager.</summary>
    public static bool IsDisabledByStartupApproved(IRegKey? approvedList, string valueName)
    {
        var b = approvedList?.GetBytes(valueName);
        return b is { Length: > 0 } && (b[0] & 1) == 1;
    }

    static void RunFamily(List<PersistenceEntry> list, IRegKey sw, string label, IRegKey? approved, string approvedList, UserProfile? user)
    {
        foreach (var rk in RunKeys)
        {
            var key = sw.Open(CV + "\\" + rk);
            if (key is null) continue;
            var approvedKey = rk == "Run" ? approved?.Open(approvedList) : null;
            foreach (var name in key.ValueNames)
            {
                var cmd = key.GetString(name);
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                list.Add(new PersistenceEntry($@"{label}\{CV}\{rk}", ValueLabel(name), cmd)
                {
                    LastWrite = key.LastWrite, User = user, Disabled = IsDisabledByStartupApproved(approvedKey, name),
                });
            }
        }

        // RunOnceEx\<sub>\<value> = "command" or "||dll|function"
        if (sw.Open(CV + @"\RunOnceEx") is { } ex)
            foreach (var sub in ex.SubKeys)
                foreach (var name in sub.ValueNames)
                {
                    var cmd = sub.GetString(name);
                    if (string.IsNullOrWhiteSpace(cmd) || name.Equals("Title", StringComparison.OrdinalIgnoreCase) || name.Equals("Flags", StringComparison.OrdinalIgnoreCase)) continue;
                    var c = cmd.StartsWith('|') ? cmd.Split('|', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? cmd : cmd;
                    list.Add(new PersistenceEntry($@"{label}\{CV}\RunOnceEx\{sub.Name}", ValueLabel(name), c) { LastWrite = sub.LastWrite, User = user });
                }

        // Policies\System\Shell replaces Explorer.
        if (sw.Open(CV + @"\Policies\System") is { } pol && pol.GetString("Shell") is { } shell && !string.IsNullOrWhiteSpace(shell) && !PersistenceRules.IsDefaultShell(shell))
            list.Add(new PersistenceEntry($@"{label}\{CV}\Policies\System", "Shell", shell, EntryKind.Winlogon) { LastWrite = pol.LastWrite, User = user });
    }

    static void Winlogon(List<PersistenceEntry> list, IRegKey sw, string label)
    {
        var wl = sw.Open(NT + @"\Winlogon");
        if (wl is null) return;
        var loc = $@"{label}\{NT}\Winlogon";
        // Only these values are read. DefaultPassword (and anything else) is never touched.
        if (wl.GetString("Shell") is { } shell && !string.IsNullOrWhiteSpace(shell) && !PersistenceRules.IsDefaultShell(shell))
            foreach (var part in SplitList(shell).Where(p => !PersistenceRules.IsDefaultShell(p)))
                list.Add(new PersistenceEntry(loc, "Shell", part, EntryKind.Winlogon) { LastWrite = wl.LastWrite });
        if (wl.GetString("Userinit") is { } ui)
            foreach (var part in SplitList(ui).Where(p => !PersistenceRules.IsDefaultUserinitPart(p)))
                list.Add(new PersistenceEntry(loc, "Userinit", part, EntryKind.Winlogon) { LastWrite = wl.LastWrite });
        foreach (var name in new[] { "Taskman", "AppSetup" })   // both empty on a normal PC
            if (wl.GetString(name) is { } v && !string.IsNullOrWhiteSpace(v))
                foreach (var part in SplitList(v))
                    list.Add(new PersistenceEntry(loc, name, part, EntryKind.Winlogon) { LastWrite = wl.LastWrite });
        if (wl.Open("Notify") is { } notify)
            foreach (var k in notify.SubKeys)
                if (k.GetString("DllName") is { } dll && !string.IsNullOrWhiteSpace(dll))
                    list.Add(new PersistenceEntry(loc + @"\Notify", k.Name, dll, EntryKind.Winlogon) { LastWrite = k.LastWrite });
        if (wl.Open("GPExtensions") is { } gp)
            foreach (var k in gp.SubKeys)
                if (k.GetString("DllName") is { } dll && !string.IsNullOrWhiteSpace(dll))
                    list.Add(new PersistenceEntry(loc + @"\GPExtensions", k.Name, dll) { LastWrite = k.LastWrite });
    }

    static void UserWinlogon(List<PersistenceEntry> list, IRegKey usw, string label, UserProfile user)
    {
        if (usw.Open(NT + @"\Winlogon") is { } wl && wl.GetString("Shell") is { } shell && !string.IsNullOrWhiteSpace(shell) && !PersistenceRules.IsDefaultShell(shell))
            list.Add(new PersistenceEntry($@"{label}\{NT}\Winlogon", "Shell", shell, EntryKind.Winlogon) { LastWrite = wl.LastWrite, User = user });
    }

    static IEnumerable<string> SplitList(string v) => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    static void AppInit(List<PersistenceEntry> list, IRegKey sw, string label)
    {
        var w = sw.Open(NT + @"\Windows");
        if (w is null || w.GetNumber("LoadAppInit_DLLs") != 1) return;
        var dlls = w.GetString("AppInit_DLLs");
        if (string.IsNullOrWhiteSpace(dlls)) return;
        foreach (var dll in dlls.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            list.Add(new PersistenceEntry($@"{label}\{NT}\Windows", "AppInit_DLLs", dll, EntryKind.DllInjection) { LastWrite = w.LastWrite });
    }

    static void Ifeo(List<PersistenceEntry> list, IRegKey sw, string label)
    {
        var ifeo = sw.Open(NT + @"\Image File Execution Options");
        var spe = sw.Open(NT + @"\SilentProcessExit");
        if (ifeo is not null)
            foreach (var k in ifeo.SubKeys)
                if (k.GetString("Debugger") is { } dbg && !string.IsNullOrWhiteSpace(dbg))
                    list.Add(new PersistenceEntry($@"{label}\{NT}\Image File Execution Options\{k.Name}", k.Name, dbg, EntryKind.IfeoDebugger) { LastWrite = k.LastWrite });
        if (spe is null) return;
        foreach (var k in spe.SubKeys)
        {
            if (k.GetString("MonitorProcess") is not { } mon || string.IsNullOrWhiteSpace(mon)) continue;
            var flag = ifeo?.Open(k.Name)?.GetNumber("GlobalFlag") ?? 0;
            bool active = (flag & 0x200) != 0;   // FLG_MONITOR_SILENT_PROCESS_EXIT
            list.Add(new PersistenceEntry($@"{label}\{NT}\SilentProcessExit\{k.Name}", k.Name, mon, EntryKind.IfeoDebugger)
            {
                LastWrite = k.LastWrite, Disabled = !active,
                Note = active ? null : "The GlobalFlag that switches this monitor on is not set.",
            });
        }
    }

    static void ActiveSetup(List<PersistenceEntry> list, IRegKey sw, string label)
    {
        var ic = sw.Open(@"Microsoft\Active Setup\Installed Components");
        if (ic is null) return;
        foreach (var k in ic.SubKeys)
        {
            if (k.GetString("StubPath") is not { } stub || string.IsNullOrWhiteSpace(stub)) continue;
            list.Add(new PersistenceEntry($@"{label}\Microsoft\Active Setup\Installed Components\{k.Name}", k.Name, stub)
            {
                LastWrite = k.LastWrite, Disabled = k.GetNumber("IsInstalled") == 0,
            });
        }
    }

    static void Netsh(List<PersistenceEntry> list, IRegKey sw, string label)
    {
        var n = sw.Open(@"Microsoft\NetSh");
        if (n is null) return;
        foreach (var name in n.ValueNames)
            if (n.GetString(name) is { } dll && !string.IsNullOrWhiteSpace(dll))
                list.Add(new PersistenceEntry($@"{label}\Microsoft\NetSh", ValueLabel(name), dll) { LastWrite = n.LastWrite });
    }

    static void BrowserPolicies(List<PersistenceEntry> list, IRegKey sw, string label, UserProfile? user)
    {
        foreach (var (browser, root) in BrowserPolicyRoots)
        {
            var policy = sw.Open(root);
            if (policy is null) continue;
            var note = $"A policy forces this extension into {browser}; this is normal on work PCs but unusual at home.";
            if (policy.Open("ExtensionInstallForcelist") is { } k)
                foreach (var name in k.ValueNames)
                    if (k.GetString(name) is { } v && !string.IsNullOrWhiteSpace(v))
                        list.Add(new PersistenceEntry($@"{label}\{root}\ExtensionInstallForcelist", ValueLabel(name), v, EntryKind.BrowserExtension)
                        { NoFile = true, LastWrite = k.LastWrite, User = user, Note = note });
            // ExtensionSettings: one JSON value, {"<id>": {"installation_mode": "force_installed", "update_url": ...}}
            if (policy.GetString("ExtensionSettings") is { Length: > 0 } json)
                foreach (var (id, mode, url) in ForcedInSettings(json))
                    list.Add(new PersistenceEntry($@"{label}\{root}", "ExtensionSettings: " + id, url is null ? id : $"{id};{url}", EntryKind.BrowserExtension)
                    { NoFile = true, LastWrite = policy.LastWrite, User = user, Note = $"{note} ({mode})" });
        }

        // Firefox: Policies\Mozilla\Firefox\Extensions\Install = list of extension URLs or files.
        if (sw.Open(@"Policies\Mozilla\Firefox\Extensions\Install") is { } ff)
            foreach (var name in ff.ValueNames)
                if (ff.GetString(name) is { } v && !string.IsNullOrWhiteSpace(v))
                    list.Add(new PersistenceEntry($@"{label}\Policies\Mozilla\Firefox\Extensions\Install", ValueLabel(name), v, EntryKind.BrowserExtension)
                    { NoFile = true, LastWrite = ff.LastWrite, User = user, Note = "A policy installs this extension into Firefox; this is normal on work PCs but unusual at home." });
    }

    /// <summary>Extensions an ExtensionSettings policy installs (force_installed / normal_installed). Bad JSON yields nothing.</summary>
    public static IEnumerable<(string Id, string Mode, string? UpdateUrl)> ForcedInSettings(string json)
    {
        var found = new List<(string, string, string?)>();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) return found;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                var mode = p.Value.TryGetProperty("installation_mode", out var m) && m.ValueKind == System.Text.Json.JsonValueKind.String ? m.GetString() : null;
                if (mode is not ("force_installed" or "normal_installed")) continue;
                var url = p.Value.TryGetProperty("update_url", out var u) && u.ValueKind == System.Text.Json.JsonValueKind.String ? u.GetString() : null;
                found.Add((p.Name, mode, url));
            }
        }
        catch (System.Text.Json.JsonException) { }
        return found;
    }

    static void ExternalExtensions(List<PersistenceEntry> list, IRegKey sw, string label, UserProfile? user)
    {
        foreach (var (browser, root) in ExternalExtensionRoots)
        {
            if (sw.Open(root) is not { } ext) continue;
            foreach (var k in ext.SubKeys)
            {
                var where = k.GetString("path") ?? k.GetString("update_url");
                list.Add(new PersistenceEntry($@"{label}\{root}", k.Name, where is null ? k.Name : $"{k.Name};{where}", EntryKind.BrowserExtension)
                {
                    NoFile = true, LastWrite = k.LastWrite, User = user,
                    Note = $"An installed program added this extension to {browser} outside the web store. Check you recognise it.",
                });
            }
        }
    }

    /// <summary>Command Processor\AutoRun: runs every time cmd.exe starts (normally not set).</summary>
    static void CmdAutoRun(List<PersistenceEntry> list, IRegKey sw, string label, UserProfile? user)
    {
        if (sw.Open(@"Microsoft\Command Processor") is { } cp && cp.GetString("AutoRun") is { } cmd && !string.IsNullOrWhiteSpace(cmd))
            list.Add(new PersistenceEntry($@"{label}\Microsoft\Command Processor", "AutoRun", cmd)
            { LastWrite = cp.LastWrite, User = user, Note = "It runs every time a command prompt opens." });
    }

    /// <summary>Old-style per-user Windows\Load and Windows\Run values (space- or comma-separated programs).</summary>
    static void WindowsLoadRun(List<PersistenceEntry> list, IRegKey usw, string label, UserProfile user)
    {
        if (usw.Open(NT + @"\Windows") is not { } w) return;
        foreach (var name in new[] { "Load", "Run" })
            if (w.GetString(name) is { } v && !string.IsNullOrWhiteSpace(v))
                foreach (var part in v.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    list.Add(new PersistenceEntry($@"{label}\{NT}\Windows", name, part) { LastWrite = w.LastWrite, User = user });
    }

    /// <summary>HKCU\Environment\UserInitMprLogonScript: a script run at every sign-in.</summary>
    static void LogonScript(List<PersistenceEntry> list, IRegKey nt, string label, UserProfile user)
    {
        if (nt.Open("Environment") is { } env && env.GetString("UserInitMprLogonScript") is { } s && !string.IsNullOrWhiteSpace(s))
            list.Add(new PersistenceEntry($@"{label}\Environment", "UserInitMprLogonScript", s) { LastWrite = env.LastWrite, User = user, Note = "It runs at every sign-in." });
    }

    public static bool IsDefaultOpenCommand(string? value) =>
        string.Join(' ', (value ?? "").Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) is "\"%1\" %*" or "%1 %*" or "\"%1\"";

    /// <summary>exefile etc. must open the file itself ("%1" %*); anything else runs on every program start.</summary>
    static void MachineFileTypes(List<PersistenceEntry> list, IRegKey? classes, string label)
    {
        if (classes is null) return;
        foreach (var type in HijackableClasses.Take(5))   // ms-settings / mscfile have real machine-wide handlers
            if (classes.Open(type + @"\shell\open\command") is { } k && k.GetString("") is { } cmd && !IsDefaultOpenCommand(cmd))
                list.Add(new PersistenceEntry($@"{label}\{type}\shell\open\command", type + " open command", cmd, EntryKind.Winlogon) { LastWrite = k.LastWrite });
    }

    /// <summary>A per-user open command for these types should not exist at all (program-start hijack, UAC bypass).</summary>
    static void UserFileTypes(List<PersistenceEntry> list, IRegKey? ntuserClasses, IRegKey? usrClass, string label, UserProfile user)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in new[] { ntuserClasses, usrClass })
            foreach (var type in HijackableClasses)
                if (root?.Open(type + @"\shell\open\command") is { } k && k.GetString("") is { } cmd && !string.IsNullOrWhiteSpace(cmd) && seen.Add(type))
                    list.Add(new PersistenceEntry($@"{label}\Software\Classes\{type}\shell\open\command", type + " open command", cmd, EntryKind.Winlogon)
                    { LastWrite = k.LastWrite, User = user, Note = "Only this user has it, which is how malware takes over program starts or gets past UAC." });
    }

    static void ScreenSaver(List<PersistenceEntry> list, IRegKey nt, string label, UserProfile user)
    {
        foreach (var path in new[] { @"Control Panel\Desktop", @"Software\Policies\Microsoft\Windows\Control Panel\Desktop" })
        {
            var k = nt.Open(path);
            if (k?.GetString("SCRNSAVE.EXE") is not { } scr || string.IsNullOrWhiteSpace(scr)) continue;
            var v = SourcePaths.Expand(scr.Trim().Trim('"'), "C:").ToLowerInvariant();
            bool system = !v.Contains('\\') || v.Contains(@"\windows\system32\") || v.Contains(@"\windows\syswow64\");
            if (system) continue;
            list.Add(new PersistenceEntry($@"{label}\{path}", "SCRNSAVE.EXE", scr) { LastWrite = k.LastWrite, User = user });
        }
    }

    static void ComHijack(List<PersistenceEntry> list, IRegKey? ntuserClsid, IRegKey? usrClassClsid, IRegKey?[] machineClsid, string label, UserProfile user)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in new[] { ntuserClsid, usrClassClsid })
        {
            if (root is null) continue;
            foreach (var k in root.SubKeys)
                foreach (var server in new[] { "InprocServer32", "LocalServer32" })
                {
                    var path = k.Open(server)?.GetString("");
                    if (string.IsNullOrWhiteSpace(path)) continue;
                    if (!machineClsid.Any(m => m?.Open(k.Name) is not null)) continue;   // only shadowing counts
                    if (!seen.Add(k.Name + "\\" + server)) continue;
                    list.Add(new PersistenceEntry($@"{label}\Software\Classes\CLSID", $@"{k.Name}\{server}", path, EntryKind.ComHijack) { LastWrite = k.LastWrite, User = user });
                }
        }
    }

    static void Services(List<PersistenceEntry> list, IRegKey ccs)
    {
        var services = ccs.Open("Services");
        if (services is null) return;
        foreach (var svc in services.SubKeys)
        {
            var start = svc.GetNumber("Start");
            if (start is not (0 or 1 or 2)) continue;
            var image = svc.GetString("ImagePath");
            if (string.IsNullOrWhiteSpace(image)) continue;
            string? dll = null;
            if (image.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
                dll = svc.Open("Parameters")?.GetString("ServiceDll") ?? svc.GetString("ServiceDll");
            list.Add(new PersistenceEntry($@"{HklmSys}\Services", svc.Name, image, EntryKind.Service)
            {
                Payload = string.IsNullOrWhiteSpace(dll) ? null : dll, LastWrite = svc.LastWrite,
                Note = string.IsNullOrWhiteSpace(dll) ? null : "It runs inside a shared Windows service host (svchost); the DLL was checked.",
            });
        }
    }

    static void BootExecute(List<PersistenceEntry> list, IRegKey ccs)
    {
        var sm = ccs.Open(@"Control\Session Manager");
        if (sm?.GetMulti("BootExecute") is not { } entries) return;
        foreach (var e in entries.Where(e => !string.IsNullOrWhiteSpace(e) && !PersistenceRules.IsDefaultBootExecute(e)))
            list.Add(new PersistenceEntry($@"{HklmSys}\Control\Session Manager", "BootExecute", e, EntryKind.Winlogon) { LastWrite = sm.LastWrite });
    }

    static void Lsa(List<PersistenceEntry> list, IRegKey ccs)
    {
        var lsa = ccs.Open(@"Control\Lsa");
        if (lsa is null) return;
        foreach (var name in LsaLists)
        {
            if (lsa.GetMulti(name) is not { } pkgs) continue;
            foreach (var p in pkgs.Where(p => !PersistenceRules.IsKnownLsaPackage(name, p)))
            {
                var dll = p.Contains('\\') || p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? p : p + ".dll";
                list.Add(new PersistenceEntry($@"{HklmSys}\Control\Lsa", $"{name}: {p}", dll, EntryKind.DllInjection) { LastWrite = lsa.LastWrite });
            }
        }
    }

    static void AppCertDlls(List<PersistenceEntry> list, IRegKey ccs)
    {
        var k = ccs.Open(@"Control\Session Manager\AppCertDlls");
        if (k is null) return;
        foreach (var name in k.ValueNames)
            if (k.GetString(name) is { } dll && !string.IsNullOrWhiteSpace(dll))
                list.Add(new PersistenceEntry($@"{HklmSys}\Control\Session Manager\AppCertDlls", ValueLabel(name), dll, EntryKind.DllInjection) { LastWrite = k.LastWrite });
    }

    static void PrintMonitors(List<PersistenceEntry> list, IRegKey ccs)
    {
        var m = ccs.Open(@"Control\Print\Monitors");
        if (m is null) return;
        foreach (var k in m.SubKeys)
            if (k.GetString("Driver") is { } dll && !string.IsNullOrWhiteSpace(dll))
                list.Add(new PersistenceEntry($@"{HklmSys}\Control\Print\Monitors", k.Name, dll) { LastWrite = k.LastWrite });
    }
}
