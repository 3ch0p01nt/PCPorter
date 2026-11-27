using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace PCPorter.TestKit;

/// <summary>
/// A fake old PC's Windows drive in a temp folder (tier-3 regression): real hive files written by offreg.dll, task files,
/// shortcuts and a mini winget catalog. Each planted case is one past bug or report rule; the list is in
/// docs/plans/2026-11-26-regression-testing.md. "C:\" on the old PC maps to <see cref="Root"/>.
/// </summary>
public sealed class OldPcDrive : IDisposable
{
    public const string Canary = "Hunter2Canary";
    public const string BobSid = "S-1-5-21-1111-2222-3333-1001";
    const string CV = @"Microsoft\Windows\CurrentVersion";
    const string Uninstall = CV + @"\Uninstall";
    const string Uninstall32 = @"WOW6432Node\" + Uninstall;
    const string TaskTree = @"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

    public string Root { get; } = Directory.CreateTempSubdirectory("pcporter-oldpc").FullName + "\\";

    /// <summary>Path on the fake drive for an old-PC path like C:\ProgramData\x.</summary>
    public string At(string oldPcPath) => Path.Combine(Root, oldPcPath[3..]);

    public static OldPcDrive Create()
    {
        var d = new OldPcDrive();
        d.Build();
        return d;
    }

    void Build()
    {
        var config = Directory.CreateDirectory(At(@"C:\Windows\System32\config")).FullName;
        var sd = new byte[] { 1, 0, 4, 0x80 };   // any non-empty SD = visible in Task Scheduler

        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(@"Microsoft\Windows NT\CurrentVersion", k => k.Str("SystemRoot", @"C:\Windows").Str("CurrentBuild", "19045")
                .Str("ProductName", "Windows 10 Pro").Str("EditionID", "Professional").Str("DisplayVersion", "22H2"))
            .Key(@"Microsoft\Windows NT\CurrentVersion\ProfileList\" + BobSid, k => k.Exp("ProfileImagePath", @"%SystemDrive%\Users\bob"))
            .Key(@"Microsoft\Cryptography", k => k.Str("MachineGuid", "0a1b2c3d-0000-4000-8000-00000000c0de"))
            // Bait: auto sign-in with a stored password. Its VALUE must never be read (denylist spy).
            .Key(@"Microsoft\Windows NT\CurrentVersion\Winlogon", k => k.Str("Shell", "explorer.exe").Str("Userinit", @"C:\Windows\system32\userinit.exe,")
                .Str("AutoAdminLogon", "1").Str("DefaultUserName", "bob").Str("DefaultPassword", Canary)
                .Str("Taskman", @"C:\ProgramData\Svc\svc.exe"))                                                       // normally empty
            .Key(@"Microsoft\Command Processor", k => k.Str("AutoRun", @"C:\Users\Public\a.bat"))
            .Key(@"Classes\exefile\shell\open\command", k => k.Str("", @"""C:\ProgramData\Hook\hook.exe"" ""%1"" %*"))   // every program start
            .Key(@"Classes\batfile\shell\open\command", k => k.Str("", @"""%1"" %*"))                                   // default: no finding
            .Key(@"Policies\Google\Chrome", k => k.Str("ExtensionSettings",
                """{"aaaabbbbccccddddeeeeffffgggghhhh":{"installation_mode":"force_installed","update_url":"https://evil.example/u.xml"},"*":{"installation_mode":"allowed"}}"""))
            .Key(@"Google\Chrome\Extensions\iiiijjjjkkkkllllmmmmnnnnoooopppp", k => k.Str("update_url", "https://clients2.google.com/service/update2/crx"))
            .Key(@"Policies\Mozilla\Firefox\Extensions\Install", k => k.Str("1", "https://evil.example/x.xpi"))
            // Apps
            .Key(Uninstall + @"\FamilyPhotos", k => App(k, "Family Photos", "3.0", "Small Shop"))
            .Key(Uninstall + @"\FamilyPhotos_2", k => App(k, "Family Photos", "2.0", "Small Shop"))
            .Key(Uninstall32 + @"\FamilyPhotos", k => App(k, "Family Photos", "1.0", "Small Shop"))
            .Key(Uninstall + @"\{23170F69-40C1-2701-1604-000001000000}", k => App(k, "7-Zip 26.06 (x64 edition)", "26.06", "Igor Pavlov").Num("WindowsInstaller", 1))
            .Key(Uninstall + @"\IDA Freeware 8.4", k => App(k, "IDA Freeware 8.4", "8.4", "Hex-Rays SA"))
            .Key(Uninstall + @"\jq_is1", k => App(k, "jq", "1.8", "jqlang"))
            // winget batch: upgrade code (MSI, packed GUIDs), winget's publisher rules (s.r.o.), a version-range tie-break
            .Key(Uninstall + @"\{11111111-2222-3333-4444-555555555555}", k => App(k, "Contoso Updater 7", "7.0", "Contoso").Num("WindowsInstaller", 1))
            .Key(@"Classes\Installer\UpgradeCodes\AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE", k => k.Str("11111111222233334444555555555555", ""))
            .Key(Uninstall + @"\PyCharm CE", k => App(k, "PyCharm Community Edition 2025.1", "251.1", "JetBrains s.r.o."))
            .Key(Uninstall + @"\Python 3.12", k => App(k, "Python 3.12.4 (64-bit)", "3.12.4", "Python Software Foundation"))
            .Key(Uninstall + @"\AcmeTool", k => App(k, "Tool", "1.0", "Acme"))                                     // two catalog ids: no match
            .Key(Uninstall + @"\{0D1B2C3D-1111-2222-3333-444455556666}.sdb", k => App(k, "Contoso Compatibility Fix", null, null))
            // Scheduled tasks
            .Key(TaskTree + @"\Leftover", k => k.Str("Id", "{AAAAAAAA-0000-0000-0000-000000000001}"))                  // no file, no SD, nothing to run
            .Key(TaskTree + @"\Updater", k => k.Str("Id", "{AAAAAAAA-0000-0000-0000-000000000002}"))                   // file with an action, SD removed
            .Key(TaskTree + @"\Backup", k => k.Str("Id", "{AAAAAAAA-0000-0000-0000-000000000003}").Bin("SD", sd)),     // normal
            Path.Combine(config, "SOFTWARE"));

        OffregHiveBuilder.Save(RegSpec.Root().Key("Select", k => k.Num("Current", 1).Num("Default", 1))
            .Key(@"ControlSet001\Control\ComputerName\ComputerName", k => k.Str("ComputerName", "OLDPC"))
            .Key(@"ControlSet001\Services\BadVendorSvc", k => k.Num("Start", 2).Num("Type", 16)
                .Exp("ImagePath", @"C:\Program Files\Bad Vendor\svc host.exe"))                                       // unquoted path with spaces
            .Key(@"ControlSet001\Control\Session Manager", k => k.Multi("BootExecute", "autocheck autochk *")),
            Path.Combine(config, "SYSTEM"));

        // Bait hives that must never be opened.
        File.WriteAllText(Path.Combine(config, "SAM"), "SAM " + Canary);
        File.WriteAllText(Path.Combine(config, "SECURITY"), "SECURITY " + Canary);

        var bob = Directory.CreateDirectory(At(@"C:\Users\bob")).FullName;
        OffregHiveBuilder.Save(RegSpec.Root()
            .Key(@"Software\" + CV + @"\Run", k => k
                .Str("Updater", @"%APPDATA%\x7f3kq9zpw.exe")                                                       // unsigned, AppData, random name
                .Str("Sync", @"""C:\Users\bob\AppData\Local\SyncTool\sync.exe"" --password=" + Canary))            // secret in the command
            .Key(@"Software\Microsoft\Command Processor", k => k.Str("AutoRun", @"C:\Users\bob\AppData\Local\cmdhook.exe"))
            .Key(@"Software\Microsoft\Windows NT\CurrentVersion\Windows", k => k.Str("Load", @"C:\Users\bob\AppData\Local\Temp\l.exe"))
            .Key(@"Environment", k => k.Str("UserInitMprLogonScript", @"C:\Users\bob\AppData\Roaming\logon.vbs"))
            .Key(@"Software\Classes\ms-settings\shell\open\command", k => k.Str("", @"C:\Users\bob\AppData\Local\Temp\bypass.exe"))   // UAC bypass
            .Key(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", k => k.Exp("Startup", @"%USERPROFILE%\Music\Start")),
            Path.Combine(bob, "NTUSER.DAT"));
        Text(@"C:\Users\Public\a.bat", "@echo off");
        Exe(@"C:\ProgramData\Svc\svc.exe");
        Exe(@"C:\ProgramData\Hook\hook.exe");
        Exe(@"C:\Users\bob\AppData\Local\cmdhook.exe");
        Exe(@"C:\Users\bob\AppData\Local\Temp\l.exe");
        Exe(@"C:\Users\bob\AppData\Local\Temp\bypass.exe");
        Text(@"C:\Users\bob\AppData\Roaming\logon.vbs", "WScript.Echo 1");
        Text(@"C:\Users\bob\Music\Start\run.bat", "@echo off");

        Exe(@"C:\Users\bob\AppData\Roaming\x7f3kq9zpw.exe");
        Exe(@"C:\Users\bob\AppData\Local\SyncTool\sync.exe");
        Exe(@"C:\Program Files\Bad Vendor\svc host.exe");
        Exe(@"C:\Users\Public\up.exe");
        Exe(@"C:\Users\bob\AppData\Local\Programs\Python\Python312\python.exe");
        Exe(@"C:\Tools\PortaTool\porta.exe");

        var tasks = At(@"C:\Windows\System32\Tasks");
        TaskXml.Write(tasks, @"\Updater", TaskXml.Exec(@"C:\Users\Public\up.exe"));
        TaskXml.Write(tasks, @"\Backup", TaskXml.Exec(@"C:\Program Files\Backup\backup.exe", "/quiet"));

        var startMenu = At(@"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs");
        TestLnk.Write(Path.Combine(startMenu, "Python 3.12 (64-bit).lnk"), @"C:\Users\bob\AppData\Local\Programs\Python\Python312\python.exe");
        TestLnk.Write(Path.Combine(startMenu, "PortaTool.lnk"), @"C:\Tools\PortaTool\porta.exe");

        // One real catalog (copied from this PC), so the offline signature check has the old PC's catalogs to search.
        var catRoot = Directory.CreateDirectory(At(@"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}")).FullName;
        var hostCatRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "CatRoot", "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");
        var smallest = Directory.Exists(hostCatRoot)
            ? Directory.EnumerateFiles(hostCatRoot, "*.cat").Select(f => new FileInfo(f)).OrderBy(f => f.Length).FirstOrDefault()
            : null;
        // Without a catalog every planted "unsigned" case would silently become "not checked": fail loudly instead.
        if (smallest is null) throw new InvalidOperationException($"This PC has no catalog files in {hostCatRoot}; the fake old drive needs one.");
        smallest.CopyTo(Path.Combine(catRoot, "fixture.cat"));

        WingetCatalog(At(@"C:\Program Files\WindowsApps\Microsoft.Winget.Source_2026.1126.1.0_neutral__8wekyb3d8bbwe\Public\index.db"));
    }

    static RegSpec App(RegSpec k, string name, string? version, string? publisher)
    {
        k.Str("DisplayName", name).Str("InstallDate", "20250315");
        if (version is not null) k.Str("DisplayVersion", version);
        if (publisher is not null) k.Str("Publisher", publisher);
        return k;
    }

    void Exe(string oldPcPath)
    {
        var p = At(oldPcPath);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllBytes(p, [0x4D, 0x5A, 0x90, 0x00]);   // "MZ": not a valid signed program
    }

    void Text(string oldPcPath, string content)
    {
        var p = At(oldPcPath);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, content);
    }

    /// <summary>The published catalog (index v2) plus bob's tracking catalog of what winget installed (schema 1.7).</summary>
    void WingetCatalog(string file)
    {
        WingetCatalogs.CreateV2(file,
            new CatalogPackage("7zip.7zip", ProductCodes: ["  {23170f69-40c1-2701-1604-000001000000}"]),
            new CatalogPackage("Hex-Rays.IDA.Free", ProductCodes: ["ida freeware 8.4"], NormNames: ["idafreeware"], NormPublishers: ["hexrays"]),
            new CatalogPackage("Acme.Tool", NormNames: ["tool"], NormPublishers: ["acme"]),
            new CatalogPackage("Other.Tool", NormNames: ["tool"], NormPublishers: ["acme"]),
            new CatalogPackage("jqlang.jq", NormNames: ["jq"], NormPublishers: ["jqlang"]),
            new CatalogPackage("Contoso.Updater", UpgradeCodes: ["{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"]),
            new CatalogPackage("JetBrains.PyCharm.Community", NormNames: ["pycharmcommunityedition"], NormPublishers: ["jetbrains"]),
            new CatalogPackage("Python.Python.3.11", NormNames: ["python", "python(X64)"], NormPublishers: ["pythonsoftwarefoundation"], ArpMin: "3.11.0", ArpMax: "3.11.9"),
            new CatalogPackage("Python.Python.3.12", NormNames: ["python", "python(X64)"], NormPublishers: ["pythonsoftwarefoundation"], ArpMin: "3.12.0", ArpMax: "3.12.9"));
        WingetCatalogs.CreateV1(At(@"C:\Users\bob\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\Microsoft.Winget.Source_8wekyb3d8bbwe\installed.db"),
            new CatalogPackage("SmallShop.FamilyPhotos", NormNames: ["familyphotos"], NormPublishers: ["smallshop"]));
    }

    /// <summary>Every file (size, last-write time, SHA-256) and folder (last-write time) on the drive.</summary>
    public IReadOnlyDictionary<string, string> Fingerprint()
    {
        var map = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in Directory.EnumerateDirectories(Root, "*", SearchOption.AllDirectories))
            map[Path.GetRelativePath(Root, dir) + "\\"] = $"dir {Directory.GetLastWriteTimeUtc(dir):O}";   // changes if a file was created and deleted
        foreach (var file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
        {
            var info = new FileInfo(file);
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            map[Path.GetRelativePath(Root, file)] = $"{info.Length} {info.LastWriteTimeUtc:O} {Convert.ToHexString(SHA256.HashData(fs))}";
        }
        return map;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
