using Microsoft.Data.Sqlite;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Apps;

public class WingetIndexTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-wingetidx").FullName;
    public void Dispose() { SqliteConnection.ClearAllPools(); try { Directory.Delete(_root, true); } catch (IOException) { } }

    /// <summary>A small catalog with winget's real table layout (Microsoft.Winget.Source index v2).</summary>
    string MakeIndex(string version = "2026.1126.1.0")
    {
        var dir = Path.Combine(_root, "Program Files", "WindowsApps", $"Microsoft.Winget.Source_{version}_neutral__8wekyb3d8bbwe", "Public");
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "index.db");
        using (var db = new SqliteConnection($"Data Source={file};Pooling=False"))
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE packages(rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, name TEXT NOT NULL, moniker TEXT, latest_version TEXT NOT NULL, arp_min_version TEXT, arp_max_version TEXT, hash BLOB);
                CREATE TABLE productcodes2(productcode TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(productcode, package)) WITHOUT ROWID;
                CREATE TABLE upgradecodes2(upgradecode TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(upgradecode, package)) WITHOUT ROWID;
                CREATE TABLE norm_names2(norm_name TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_name, package)) WITHOUT ROWID;
                CREATE TABLE norm_publishers2(norm_publisher TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_publisher, package)) WITHOUT ROWID;
                INSERT INTO packages(rowid,id,name,latest_version) VALUES (1,'7zip.7zip','7-Zip','26.06'),(2,'Google.Chrome','Google Chrome','158.0'),
                  (3,'Hex-Rays.IDA.Free','IDA Freeware','8.4'),(4,'Microsoft.Office','Microsoft 365 Apps for enterprise','16.0'),
                  (5,'Acme.Tool','Tool','1.0'),(6,'Other.Tool','Tool','1.0'),(7,'Contoso.App','Contoso App','2.0'),(8,'Google.Chrome.EXE','Google Chrome','158.0'),(9,'jqlang.jq','jq','1.8');
                INSERT INTO productcodes2 VALUES ('  {23170f69-40c1-2701-1604-000001000000}',1),('7-zip',1),('ida freeware 8.4',3);
                INSERT INTO upgradecodes2 VALUES ('5decba45-26fe-4118-9816-032e474c3e56',7);
                INSERT INTO norm_names2 VALUES ('googlechrome',2),('idafreeware',3),('microsoft365appsforenterprise',4),('tool',5),('tool',6),('',1),('googlechrome',8),('jq',9);
                INSERT INTO norm_publishers2 VALUES ('google',2),('hexrays',3),('microsoft',4),('acme',5),('acme',6),('google',8),('jqlang',9);
                """;
            cmd.ExecuteNonQuery();
        }
        SqliteConnection.ClearAllPools();
        return file;
    }

    static InstalledApp App(string name, string? publisher, string? productCode = null, string? upgradeCode = null, string? arpKey = null) =>
        InstalledApp.Create(name, "1.0", publisher, "x64", "Machine", AppKind.Win32,
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + (arpKey ?? productCode ?? name))
        with { ProductCode = productCode, UpgradeCode = upgradeCode };

    [Fact]
    public void Matches_by_product_code_uninstall_key_upgrade_code_then_name_and_publisher()
    {
        MakeIndex();
        using var index = WingetIndex.Open(new FakeSystemSource(_root), out var why)!;
        Assert.Null(why);
        List<InstalledApp> apps =
        [
            App("7-Zip 26.06 (x64 edition)", "Igor Pavlov", productCode: "{23170F69-40C1-2701-1604-000001000000}"),   // MSI code (catalog has padding)
            App("IDA Freeware 8.4", "Hex-Rays SA", arpKey: "IDA Freeware 8.4"),                                    // uninstall key name
            App("Contoso App", "Contoso", upgradeCode: "5DECBA45-26FE-4118-9816-032E474C3E56"),
            App("Google Chrome", "Google LLC"),                                                                     // name + publisher; parent of .EXE variant
            App("jq", "jqlang"),                                                                                    // short name is fine with a publisher
            App("Microsoft 365 Apps for enterprise - en-us", "Microsoft Corporation"),                              // locale stripped
            App("Tool", "Acme Inc."),                                                                               // two packages: never guess
            App("Google Chrome", "Not Google"),                                                                     // publisher differs
            InstalledApp.Create("Photos", null, "Microsoft Corporation", "x64", "User:bob", AppKind.Store, "appx:photos"),
        ];
        Assert.Equal(6, index.Match(apps));
        Assert.Equal(["7zip.7zip", "Hex-Rays.IDA.Free", "Contoso.App", "Google.Chrome", "jqlang.jq", "Microsoft.Office", null, null, null], apps.Select(a => a.WingetId));
        Assert.Equal(["ProductCode", "ProductCode", "ProductCode", "NameMatch", "NameMatch", "NameMatch"], apps.Take(6).Select(a => a.MatchMethod));
    }

    static readonly UserProfile BobProfile = new("S-1-5-21-1-2-3-1001", "bob", null, null);
    const string Tracking = @"Users\bob\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState";

    [Fact]
    public void Tracking_catalogs_name_the_winget_and_store_ids_of_what_winget_installed()
    {
        WingetCatalogs.CreateV1(Path.Combine(_root, Tracking, "Microsoft.Winget.Source_8wekyb3d8bbwe", "installed.db"),
            // Two Pythons share every name: only the version range tells them apart.
            new CatalogPackage("Python.Python.3.11", "3.11.9", NormNames: ["python", "python(X64)"], NormPublishers: ["pythonsoftwarefoundation"], ArpMin: "3.11.0", ArpMax: "3.11.9"),
            new CatalogPackage("Python.Python.3.12", "3.12.4", NormNames: ["python", "python(X64)"], NormPublishers: ["pythonsoftwarefoundation"], ArpMin: "3.12.0", ArpMax: "3.12.4"),
            new CatalogPackage("Contoso.Msi", ProductCodes: ["{11111111-2222-3333-4444-555555555555}"]),
            new CatalogPackage("Contoso.Updater", UpgradeCodes: ["{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"]));
        WingetCatalogs.CreateV1(Path.Combine(_root, Tracking, "StoreEdgeFD", "installed.db"),
            new CatalogPackage("XPDCK2L0R6V76J", Pfns: ["Contoso.Notes_8wekyb3d8bbwe"]));
        var src = new FakeSystemSource(_root, users: [BobProfile with { ProfilePath = Path.Combine(_root, "Users", "bob") }]);

        var notes = new List<string>();
        var records = WingetIndex.OpenTracking(src, notes);
        Assert.Empty(notes);
        Assert.Equal(["winget", "msstore"], records.Select(r => r.Source));
        Assert.All(records, r => Assert.Equal("1.7", r.SchemaVersion));

        List<InstalledApp> apps =
        [
            App("Python 3.12.4 (64-bit)", "Python Software Foundation") with { Version = "3.12.4" },
            App("Python 3.11.9 (64-bit)", "Python Software Foundation") with { Version = "3.11.9" },
            App("Contoso MSI", "Contoso", productCode: "{11111111-2222-3333-4444-555555555555}"),
            App("Contoso Updater 7", "Contoso", upgradeCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
            InstalledApp.Create("Notes", "1.0", "Contoso", "x64", "User:bob", AppKind.Store, "appx:notes") with { PackageFamilyName = "Contoso.Notes_8wekyb3d8bbwe" },
        ];
        foreach (var r in records) r.Match(apps);
        Assert.Equal(["Python.Python.3.12", "Python.Python.3.11", "Contoso.Msi", "Contoso.Updater", "XPDCK2L0R6V76J"], apps.Select(a => a.WingetId));
        Assert.Equal(["winget", "winget", "winget", "winget", "msstore"], apps.Select(a => a.WingetSource));
        Assert.All(apps, a => Assert.Equal(WingetIndex.TrackedMethod, a.MatchMethod));
    }

    [Fact]
    public void Store_apps_match_the_published_catalog_by_package_family_name()
    {
        var file = Path.Combine(_root, "v2", "index.db");
        WingetCatalogs.CreateV2(file, new CatalogPackage("Microsoft.WindowsTerminal", Pfns: ["Microsoft.WindowsTerminal_8wekyb3d8bbwe"]));
        var index = WingetIndex.OpenFile(file);
        Assert.Equal("2.0", index.SchemaVersion);
        List<InstalledApp> apps = [InstalledApp.Create("Windows Terminal", "1.22", "Microsoft Corporation", "x64", "User:bob", AppKind.Store, "appx:wt")
            with { PackageFamilyName = "Microsoft.WindowsTerminal_8wekyb3d8bbwe" }];
        Assert.Equal(1, index.Match(apps));
        Assert.Equal(("Microsoft.WindowsTerminal", "ProductCode"), (apps[0].WingetId, apps[0].MatchMethod));
    }

    [Fact]
    public void An_unknown_catalog_layout_is_a_note_not_a_crash()
    {
        var file = Path.Combine(_root, Tracking, "Microsoft.Winget.Source_8wekyb3d8bbwe", "installed.db");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        using (var db = new SqliteConnection($"Data Source={file};Pooling=False")) { db.Open(); using var c = db.CreateCommand(); c.CommandText = "CREATE TABLE other(x)"; c.ExecuteNonQuery(); }
        SqliteConnection.ClearAllPools();
        var notes = new List<string>();
        Assert.Empty(WingetIndex.OpenTracking(new FakeSystemSource(_root, users: [BobProfile with { ProfilePath = Path.Combine(_root, "Users", "bob") }]), notes));
        Assert.Contains(notes, n => n.Contains("could not be read"));
    }

    [Fact]
    public void Newest_catalog_wins_and_a_missing_catalog_is_a_note()
    {
        Assert.Null(WingetIndex.Open(new FakeSystemSource(_root), out var why));
        Assert.Contains("not found", why);
        var older = MakeIndex("2025.1.1.0");
        var newer = MakeIndex("2026.11.1.0");
        using var index = WingetIndex.Open(new FakeSystemSource(_root), out _)!;
        Assert.Equal(newer, index.Path);
        Assert.NotEqual(older, index.Path);
    }

    [Fact]
    public void Reading_the_catalog_leaves_no_files_behind()
    {
        var file = MakeIndex();
        var before = Directory.GetFiles(Path.GetDirectoryName(file)!).Length;
        var stamp = File.GetLastWriteTimeUtc(file);
        using (var index = WingetIndex.Open(new FakeSystemSource(_root), out _)) Assert.Equal(9, index!.PackageCount);
        Assert.Equal(before, Directory.GetFiles(Path.GetDirectoryName(file)!).Length);   // no -wal/-shm/-journal
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(file));
    }

    [Theory]
    [InlineData("IDA Freeware 8.4", "idafreeware")]
    [InlineData("7-Zip 26.06 (x64)", "7zip")]
    [InlineData("Microsoft 365 Apps for enterprise - en-us", "microsoft365appsforenterprise")]
    [InlineData("Notepad++ (64-bit x64)", "notepad")]
    [InlineData("Google Chrome", "googlechrome")]
    [InlineData("Microsoft Visual Studio Code (User)", "microsoftvisualstudiocode")]
    public void Names_normalize_like_winget(string name, string expected) => Assert.Equal(expected, WingetIndex.NormalizeName(name));

    [Theory]
    [InlineData("Google LLC", "google")]
    [InlineData("Microsoft Corporation", "microsoft")]
    [InlineData("Hex-Rays SA", "hexrays")]
    [InlineData("Igor Pavlov", "igorpavlov")]
    [InlineData("Acme, Inc.", "acme")]
    public void Publishers_normalize_like_winget(string pub, string expected) => Assert.Equal(expected, WingetIndex.NormalizePublisher(pub));
}
