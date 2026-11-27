using System.Diagnostics;
using PCPorter.Collectors.Apps;
using PCPorter.TestKit;
using static PCPorter.Collectors.Tests.Apps.AppTest;

namespace PCPorter.Collectors.Tests.Apps;

public class PackageManagerTests : IDisposable
{
    readonly FakeDrive _d = new();
    public void Dispose() => _d.Dispose();

    const string Nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
          <metadata>
            <id>git.install</id>
            <version>2.43.0</version>
            <title>Git (Install)</title>
            <authors>The Git Development Community</authors>
            <dependencies><dependency id="chocolatey-core.extension" version="1.1.0" /></dependencies>
          </metadata>
        </package>
        """;

    void Choco(string id, string nuspec) => _d.Write($@"C:\ProgramData\chocolatey\lib\{id}\{id}.nuspec", nuspec);

    static string SimpleNuspec(string id, string version, string? title = null) =>
        $"""<?xml version="1.0"?><package><metadata><id>{id}</id><version>{version}</version>{(title is null ? "" : $"<title>{title}</title>")}</metadata></package>""";

    [Fact]
    public void Nuspec_id_version_title()
    {
        Choco("git.install", Nuspec);
        Assert.Equal(("git.install", "2.43.0", "Git (Install)"), PackageManagersInventory.ParseNuspec(_d.At(@"C:\ProgramData\chocolatey\lib\git.install\git.install.nuspec")));
    }

    [Fact]
    public void Chocolatey_packages_attach_to_registry_apps_or_are_added()
    {
        Choco("git.install", Nuspec);
        Choco("ripgrep", SimpleNuspec("ripgrep", "14.1.0"));
        Choco("chocolatey", SimpleNuspec("chocolatey", "2.2.2"));
        Choco("chocolatey-core.extension", SimpleNuspec("chocolatey-core.extension", "1.4.0"));
        Choco("broken", "<package><metadata><id>oops");
        var sw = RegSpec.Root().Key(Uninstall + @"\Git_is1", k => k.Str("DisplayName", "Git").Str("DisplayVersion", "2.43.0")).Key(Uninstall32);
        var src = new FakeSystemSource(_d.Root, sw);

        var (apps, _, warnings) = Run(src, _d.Work, new AppInventoryOptions(Games: false, StoreApps: false, Portable: false, Winget: false));

        Assert.Equal("git.install", apps.Single(a => a.Name == "Git").ChocoId);
        var rg = apps.Single(a => a.ChocoId == "ripgrep");
        Assert.Equal(("ripgrep", "14.1.0", "Machine", "choco:ripgrep"), (rg.Name, rg.Version, rg.Scope, rg.SourceKey));
        Assert.Equal(2, apps.Count);                                      // chocolatey itself and extensions are not apps
        Assert.Single(warnings);                                          // the broken nuspec
    }

    [Fact]
    public void Scoop_apps_per_user_with_bucket_and_architecture()
    {
        var bob = BobOn(_d);
        _d.Write(@"C:\Users\bob\scoop\apps\ripgrep\current\manifest.json", """{ "version": "14.1.0", "description": "x" }""");
        _d.Write(@"C:\Users\bob\scoop\apps\ripgrep\current\install.json", """{ "bucket": "main", "architecture": "64bit" }""");
        _d.Write(@"C:\Users\bob\scoop\apps\scoop\current\manifest.json", """{ "version": "0.4" }""");
        _d.Write(@"C:\Users\bob\scoop\apps\bad\current\manifest.json", "{ not json");
        var src = new FakeSystemSource(_d.Root, RegSpec.Root(), users: [bob]);

        var (apps, _, warnings) = Run(src, _d.Work, new AppInventoryOptions(Games: false, StoreApps: false, Portable: false, Winget: false));

        var rg = Assert.Single(apps);
        Assert.Equal(("ripgrep", "14.1.0", "User:bob", "x64", "ripgrep", "scoop:main/ripgrep"), (rg.Name, rg.Version, rg.Scope, rg.Architecture, rg.ScoopId, rg.SourceKey));
        Assert.Single(warnings);
    }

    [Fact]
    public void Scoop_current_junction_is_not_followed_off_the_drive()
    {
        var bob = BobOn(_d);
        _d.Write(@"C:\Users\bob\scoop\apps\jq\1.7.1\manifest.json", """{ "version": "1.7.1" }""");
        // A junction whose target is a path on THIS PC (outside the scanned drive): must not be read.
        var outside = Directory.CreateTempSubdirectory("pcporter-outside").FullName;
        File.WriteAllText(Path.Combine(outside, "manifest.json"), """{ "version": "666" }""");
        var link = _d.At(@"C:\Users\bob\scoop\apps\jq\current");
        if (!MakeJunction(link, outside)) { Directory.Delete(outside, true); return; }   // mklink unavailable: nothing to check
        try
        {
            var src = new FakeSystemSource(_d.Root, RegSpec.Root(), users: [bob]);
            var (apps, _, _) = Run(src, _d.Work, new AppInventoryOptions(Games: false, StoreApps: false, Portable: false, Winget: false));
            Assert.Equal("1.7.1", Assert.Single(apps).Version);
        }
        finally { Directory.Delete(link); Directory.Delete(outside, true); }
    }

    static bool MakeJunction(string link, string target)
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var psi = new ProcessStartInfo(cmd) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "/c", "mklink", "/J", link, target }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit(10000);
        return p.ExitCode == 0 && Directory.Exists(link);
    }
}

public class GameLibraryTests : IDisposable
{
    readonly FakeDrive _d = new();
    public void Dispose() => _d.Dispose();

    static string Acf(string id, string name, string dir) => $$"""
        "AppState"
        {
            "appid"     "{{id}}"
            "name"      "{{name}}"
            "installdir"    "{{dir}}"
            "buildid"   "1234"
            "LastUpdated"   "1700000000"
        }
        """;

    [Fact]
    public void Steam_libraries_and_manifests()
    {
        _d.Write(@"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf", VdfTests.LibraryFolders);
        _d.Write(@"C:\Program Files (x86)\Steam\steamapps\appmanifest_440.acf", Acf("440", "Team Fortress 2", "Team Fortress 2"));
        _d.Write(@"C:\Program Files (x86)\Steam\steamapps\appmanifest_228980.acf", Acf("228980", "Steamworks Common Redistributables", "Steamworks Shared"));
        _d.Write(@"C:\Games\SteamLib\steamapps\appmanifest_570.acf", Acf("570", "Dota 2", "dota 2 beta"));
        _d.Write(@"C:\Games\SteamLib\steamapps\appmanifest_9.acf", "garbage {{{");
        var sw = RegSpec.Root()
            .Key(@"WOW6432Node\Valve\Steam", k => k.Str("InstallPath", @"C:\Program Files (x86)\Steam"))
            .Key(Uninstall32 + @"\Steam App 440", k => k.Str("DisplayName", "Steam App 440"))
            .Key(Uninstall + @"\Mod", k => k.Str("DisplayName", "Some Mod Tool").Str("InstallLocation", @"C:\Games\SteamLib\steamapps\common\Mod"));
        var src = new FakeSystemSource(_d.Root, sw);

        var (apps, output, warnings) = Run(src, _d.Work, new AppInventoryOptions(PackageManagers: false, StoreApps: false, Portable: false, Winget: false));

        Assert.Empty(warnings);
        var tf2 = Assert.Single(apps, a => a.Name == "Team Fortress 2");          // registry "Steam App 440" renamed, not duplicated
        Assert.Equal(AppKind.Game, tf2.Kind);
        Assert.EndsWith(@"\Steam App 440", tf2.SourceKey);
        var dota = apps.Single(a => a.Name == "Dota 2");
        Assert.Equal((AppKind.Game, @"C:\Games\SteamLib\steamapps\common\dota 2 beta", "steam:570", true), (dota.Kind, dota.InstallLocation, dota.SourceKey, dota.ReinstallCandidate));
        Assert.Equal(new DateOnly(2023, 11, 14), dota.InstallDate);
        Assert.Equal(AppKind.Game, apps.Single(a => a.Name == "Some Mod Tool").Kind);      // under a Steam library
        Assert.DoesNotContain(apps, a => a.Name.StartsWith("Steamworks"));
        Assert.Equal(3, apps.Count);
        Assert.Contains(output.Notes, n => n.Contains("another drive"));                   // D:\SteamLibrary
    }

    [Fact]
    public void Epic_manifests()
    {
        _d.Write(@"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\ABC.item", """
            { "FormatVersion": 0, "bIsIncompleteInstall": false, "DisplayName": "Rocket League",
              "InstallLocation": "C:\\Program Files\\Epic Games\\rocketleague", "AppName": "Sugar", "AppVersionString": "2.41" }
            """);
        _d.Write(@"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\DEF.item", """{ "DisplayName": "Half Done", "bIsIncompleteInstall": true }""");
        _d.Write(@"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\BAD.item", "{ nope");
        var src = new FakeSystemSource(_d.Root, RegSpec.Root());

        var (apps, _, warnings) = Run(src, _d.Work, new AppInventoryOptions(PackageManagers: false, StoreApps: false, Portable: false, Winget: false));

        var rl = Assert.Single(apps);
        Assert.Equal(("Rocket League", "2.41", AppKind.Game, "epic:Sugar", @"C:\Program Files\Epic Games\rocketleague"),
            (rl.Name, rl.Version, rl.Kind, rl.SourceKey, rl.InstallLocation));
        Assert.Single(warnings);
    }
}

public class PortableAndStoreTests : IDisposable
{
    readonly FakeDrive _d = new();
    public void Dispose() => _d.Dispose();

    [Fact]
    public void Lnk_target_is_read_from_the_binary_file()
    {
        var lnk = _d.At(@"C:\x\Tool.lnk");
        TestLnk.Write(lnk, @"C:\Tools\Thing\thing.exe");
        Assert.Equal(@"C:\Tools\Thing\thing.exe", PortableAppFinder.ReadTarget(lnk));
        File.WriteAllBytes(_d.At(@"C:\x\Bad.lnk"), [1, 2, 3]);
        Assert.Null(PortableAppFinder.ReadTarget(_d.At(@"C:\x\Bad.lnk")));
    }

    [Fact]
    public void Shortcuts_to_exes_outside_known_app_folders_are_portable()
    {
        var bob = BobOn(_d);
        const string menu = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";
        TestLnk.Write(_d.At(menu + @"\Tools\Thing.lnk"), @"C:\Tools\Thing\thing.exe");          // portable
        TestLnk.Write(_d.At(menu + @"\Installed.lnk"), @"C:\Apps\Installed\app.exe");          // under InstallLocation
        TestLnk.Write(_d.At(menu + @"\Pf.lnk"), @"C:\Program Files\Vendor\v.exe");             // Program Files
        TestLnk.Write(_d.At(menu + @"\Win.lnk"), @"C:\Windows\System32\notepad.exe");          // Windows
        TestLnk.Write(_d.At(menu + @"\Doc.lnk"), @"C:\Tools\readme.txt");                      // not an exe
        TestLnk.Write(_d.At(@"C:\Users\bob\Desktop\Thing again.lnk"), @"C:\Tools\Thing\thing.exe");    // duplicate target
        TestLnk.Write(_d.At(@"C:\Users\bob\Desktop\Other.lnk"), @"D:\PortableApps\other\other.exe");    // portable, other drive
        TestLnk.Write(_d.At(@"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Unins.lnk"), @"C:\Squirrel\Update.exe");
        var sw = RegSpec.Root()
            .Key(Uninstall + @"\Installed", k => k.Str("DisplayName", "Installed").Str("InstallLocation", @"C:\Apps\Installed\"))
            .Key(Uninstall + @"\Sq", k => k.Str("DisplayName", "Squirrel App").Str("UninstallString", @"""C:\Squirrel\Update.exe"" --uninstall"))
            .Key(Uninstall32);
        var src = new FakeSystemSource(_d.Root, sw, users: [bob], userHives: new Dictionary<string, RegSpec> { [bob.Sid] = RegSpec.Root() });

        var (apps, output, _) = Run(src, _d.Work, new AppInventoryOptions(Games: false, PackageManagers: false, StoreApps: false, Winget: false));

        var portable = apps.Where(a => a.Kind == AppKind.Portable).OrderBy(a => a.Name).ToList();
        Assert.Equal(["Other", "Thing"], portable.Select(a => a.Name));
        Assert.Equal((@"C:\Tools\Thing", "Machine"), (portable[1].InstallLocation, portable[1].Scope));
        Assert.Equal("User:bob", portable[0].Scope);
        Assert.Contains(output.Notes, n => n.Contains("copy their folders"));
    }

    [Fact]
    public void Offline_store_apps_are_a_note_and_winget_does_not_run()
    {
        var src = new FakeSystemSource(_d.Root, RegSpec.Root());
        var (apps, output, warnings) = Run(src, _d.Work, new AppInventoryOptions());
        Assert.Empty(apps);
        Assert.Empty(warnings);
        Assert.Contains(AppxInventory.OfflineNote, output.Notes);
        Assert.False(File.Exists(Path.Combine(_d.Work, "winget.json")));                     // winget.exe never runs offline
        Assert.Contains(output.Notes, n => n.Contains("winget's package list was not found"));
        Assert.Equal(CollectorStatus.Ok, output.Status);
    }

    [AdminFact, Trait("Category", "Admin")]
    public void Elevated_run_never_starts_winget_and_uses_the_catalog_instead()
    {
        var notes = new List<string>();
        WingetMatcher.Apply(Context(new FakeSystemSource(_d.Root, live: true), _d.Work), [], notes, CancellationToken.None);
        Assert.Contains(notes, n => n.Contains("winget's package list"));
        Assert.False(File.Exists(Path.Combine(_d.Work, "winget.json")));
    }
}

public class WingetMatcherTests
{
    const string Export = """
        {
          "$schema": "https://aka.ms/winget-packages.schema.2.0.json",
          "CreationDate": "2026-11-26T10:00:00.000-00:00",
          "Sources": [
            {
              "Packages": [
                { "PackageIdentifier": "Git.Git", "Version": "2.43.0" },
                { "PackageIdentifier": "Microsoft.VisualStudioCode", "Version": "1.95.0" },
                { "PackageIdentifier": "Mozilla.Firefox", "Version": "121.0" },
                { "PackageIdentifier": "ARP\\Machine\\X64\\SomethingLocal" },
                { "PackageIdentifier": "Nobody.Installed", "Version": "1.0" },
                { "Version": "no id" }
              ],
              "SourceDetails": { "Argument": "https://cdn.winget.microsoft.com/cache", "Identifier": "Microsoft.Winget.Source_8wekyb3d8bbwe", "Name": "winget", "Type": "Microsoft.PreIndexed.Package" }
            }
          ],
          "WinGetVersion": "1.9.25200"
        }
        """;

    [Fact]
    public void Parses_export_and_ignores_arp_ids()
    {
        var pkgs = WingetMatcher.ParseExport(Export);
        Assert.Equal(["Git.Git", "Microsoft.VisualStudioCode", "Mozilla.Firefox", "Nobody.Installed"], pkgs.Select(p => p.Id));
        Assert.All(pkgs, p => Assert.Equal("winget", p.Source));
        Assert.Equal("2.43.0", pkgs[0].Version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{ broken")]
    [InlineData("[]")]
    [InlineData("""{ "Sources": 5 }""")]
    public void Bad_export_is_empty_not_an_exception(string json) => Assert.Empty(WingetMatcher.ParseExport(json));

    static InstalledApp App(string name, string? version, AppKind kind = AppKind.Win32) =>
        InstalledApp.Create(name, version, null, "x64", "Machine", kind, "test:" + name);

    [Fact]
    public void Matches_by_normalized_name_and_marks_the_rest_none()
    {
        var apps = new List<InstalledApp>
        {
            App("Git", "2.43.0"),
            App("Microsoft Visual Studio Code (User)", "1.95.0"),
            App("Mozilla Firefox (x64 en-US)", "121.0"),
            App("Paint.NET", "5.0"),
            App("Firefox Store", "1.0", AppKind.Store),
        };
        var matched = WingetMatcher.Match(apps, WingetMatcher.ParseExport(Export));

        Assert.Equal(3, matched);
        Assert.Equal("Git.Git", apps[0].WingetId);
        Assert.Equal("Microsoft.VisualStudioCode", apps[1].WingetId);
        Assert.Equal("Mozilla.Firefox", apps[2].WingetId);
        Assert.Equal(("winget", WingetMatcher.Method), (apps[0].WingetSource, apps[0].MatchMethod));
        Assert.Equal(("None", (string?)null), (apps[3].MatchMethod, apps[3].WingetId));
        Assert.Null(apps[4].MatchMethod);
    }

    [Fact]
    public void Prefix_match_needs_the_same_version()
    {
        var apps = new List<InstalledApp> { App("Git Extensions", "4.0") };
        WingetMatcher.Match(apps, [new WingetPackage("Git.Git", "2.43.0", "winget")]);
        Assert.Null(apps[0].WingetId);
    }
}
