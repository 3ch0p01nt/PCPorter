using PCPorter.Collectors;
using PCPorter.Collectors.Health;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class HealthReportTests : IDisposable
{
    readonly string _out = Directory.CreateTempSubdirectory("pcporter-health").FullName;
    public void Dispose() { try { Directory.Delete(_out, true); } catch (IOException) { } }

    sealed class Fake(string name, Func<CollectorOutput> run) : ICollector
    {
        public string Name => name;
        public CollectorOutput Run(CollectorContext context, CancellationToken ct) => run();
    }

    static PersistenceItem Startup(string name, Severity sev, string command, bool disabled = false) =>
        new(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", name, command, null, null, null, SignatureStatus.Unsigned, sev, "unsigned-user-folder",
            "Runs from a user folder and is not signed.", disabled, null);

    ScanJobResult Scan(params ICollector[] collectors) =>
        ScanJob.Run(_out, new ScanJobOptions(), _ => collectors, writeReport: HealthReport.Write);

    [Fact]
    public void Report_is_written_redacted_and_escaped()
    {
        var r = Scan(
            new Fake("Startup", () => new("persistence",
            [
                Startup("<script>alert(1)</script>", Severity.High, @"C:\Users\bob\x.exe --password=Hunter2"),
                Startup("helper", Severity.Medium, "helper.exe"),
                Startup("old", Severity.High, "old.exe", disabled: true),
            ], [])),
            new Fake("Settings", () => new("posture",
            [
                new PostureCheck("firewall", "Firewall", PostureStatus.Risk, PostureSeverity.High, "The firewall is off.", "Turn it on.", "EnableFirewall=0"),
                new PostureCheck("uac", "User Account Control", PostureStatus.Good, PostureSeverity.Info, "On.", "", "EnableLUA=1"),
            ], [])),
            new Fake("Profile", () => new("profile", [new PcProfile { ComputerName = "OLDPC", RamBytes = 16L << 30 }], [])));

        Assert.NotNull(r.ReportPath);
        var html = File.ReadAllText(r.ReportPath!);
        Assert.DoesNotContain("Hunter2", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Needs attention", html);                    // firewall at Risk/High
        Assert.Contains("Read-only scan. Nothing was changed or sent anywhere.", html);
        Assert.Contains("default-src 'none'", html);                  // no network, no scripts

        var f = ScanSetup.CountFindings(r);
        Assert.Equal(2, f.WorthALook);                                // one High startup + one Risk setting
        Assert.Equal(2, f.Unusual);                                   // the Medium one + the High one that is turned off
    }

    [Fact]
    public void Clean_scan_says_looks_good()
    {
        var r = Scan(new Fake("Settings", () => new("posture",
            [new PostureCheck("uac", "User Account Control", PostureStatus.Good, PostureSeverity.Info, "On.", "", "")], [])));
        var html = File.ReadAllText(r.ReportPath!);
        Assert.Contains("Looks good", html);
        Assert.Contains("Nothing to do.", html);
    }

    [Fact]
    public void Several_versions_of_one_app_are_one_row()
    {
        static PCPorter.Collectors.Apps.InstalledApp A(string name, string ver, string? winget = null) =>
            PCPorter.Collectors.Apps.InstalledApp.Create(name, ver, "Contoso", "x64", "Machine", PCPorter.Collectors.Apps.AppKind.Win32, "k:" + name + ver)
            with { WingetId = winget };
        var rows = HealthReport.ReinstallRows([A("Stack", "1.0.9"), A("Stack", "1.0.10"), A("Stack", "1.0.2"), A("Other", "2.0", "Contoso.Other")]);
        Assert.Equal(2, rows.Count);
        var stack = rows.Single(r => r.App.Name == "Stack");
        Assert.Equal(("1.0.10", 3), (stack.App.Version, stack.Copies));   // newest version shown, by version not text order
    }

    [Fact]
    public void Unusual_settings_are_labelled_unusual_and_not_urgent()
    {
        var r = Scan(new Fake("Settings", () => new("posture",
        [
            new PostureCheck("rdp", "Remote Desktop", PostureStatus.Attention, PostureSeverity.Low, "Remote Desktop is on.", "Turn it off if unused.", ""),
            new PostureCheck("sac", "Smart App Control", PostureStatus.Attention, PostureSeverity.Info, "Smart App Control is off.", "No action needed.", ""),
        ], [])));
        var html = File.ReadAllText(r.ReportPath!);
        Assert.Contains("Mostly fine", html);
        Assert.Contains("Worth checking when you have time", html);
        Assert.DoesNotContain("<h2>Do these things</h2>", html);
        Assert.DoesNotContain(">Worth a look</span>", html);                    // banner says 0 worth a look: no row may say it
        var todo = html[html.IndexOf("id=\"todo\"")..html.IndexOf("id=\"security\"")];
        Assert.Contains("Remote Desktop", todo);
        Assert.DoesNotContain("Smart App Control", todo);                       // "no action needed" stays off the to-do list
    }

    [Fact]
    public void A_failed_check_is_called_out()
    {
        var r = Scan(new Fake("Broken", () => throw new IOException("nope")));
        var html = File.ReadAllText(r.ReportPath!);
        Assert.Contains("Some checks could not finish", html);
        Assert.Contains("<h1>Incomplete check</h1>", html);               // never "Looks good" when a part is missing
        Regression.ReportInvariants.AssertHolds(html);
    }

    static string Html(ScanJobResult r) => File.ReadAllText(r.ReportPath!);

    [Fact]
    public void A_stopped_scan_never_says_looks_good_and_marks_the_unfinished_list()
    {
        using var cts = new CancellationTokenSource();
        var r = ScanJob.Run(_out, new ScanJobOptions(), _ =>
        [
            new Fake("Settings", () => new("posture", [new PostureCheck("uac", "User Account Control", PostureStatus.Good, PostureSeverity.Info, "On.", "", "")], [])),
            new Fake("Startup", () => { cts.Cancel(); return new("persistence", [Startup("helper", Severity.Info, "helper.exe")], [], CollectorStatus.Cancelled); }),
            new Fake("Apps", () => new("apps", [], [])),
        ], ct: cts.Token, writeReport: HealthReport.Write);
        Assert.True(r.Run.Cancelled);
        var html = Html(r);
        Assert.Contains("<h1>Incomplete check</h1>", html);
        Assert.DoesNotContain("Looks good", html);
        Assert.DoesNotContain("didn't find anything", html);
        Assert.Contains("The scan was stopped early", html);
        var startup = html[html.IndexOf("<h3>Programs that start with Windows</h3>")..html.IndexOf("id=\"moving\"")];
        Assert.Contains("This list is incomplete", startup);                // the startup check was stopped part-way
        var moving = html[html.IndexOf("id=\"moving\"")..html.IndexOf("id=\"hardware\"")];
        Assert.Contains("did not run", moving);                           // never started
        Regression.ReportInvariants.AssertHolds(html);
    }

    [Fact]
    public void Findings_in_a_stopped_scan_keep_their_verdict()
    {
        using var cts = new CancellationTokenSource();
        var r = ScanJob.Run(_out, new ScanJobOptions(), _ =>
        [
            new Fake("Settings", () => { cts.Cancel(); return new("posture",
                [new PostureCheck("firewall", "Firewall", PostureStatus.Risk, PostureSeverity.High, "The firewall is off.", "Turn it on.", "")], [], CollectorStatus.Cancelled); }),
        ], ct: cts.Token, writeReport: HealthReport.Write);
        var html = Html(r);
        Assert.Contains("<h1>Needs attention</h1>", html);                // what was found is real
        Assert.Contains("The scan was stopped early", html);
        Regression.ReportInvariants.AssertHolds(html);
    }

    [Fact]
    public void A_partly_read_check_keeps_looks_good_with_the_partial_line()
    {
        var r = Scan(new Fake("Settings", () => new("posture",
            [new PostureCheck("uac", "User Account Control", PostureStatus.Good, PostureSeverity.Info, "On.", "", "")], ["1 check could not be read."], CollectorStatus.Partial)));
        var html = Html(r);
        Assert.Contains("<h1>Looks good</h1>", html);
        Assert.Contains("Nothing stood out in the parts we could check.", html);
        Assert.Contains("Some checks could not finish", html);
    }
}
