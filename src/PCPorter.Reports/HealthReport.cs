using System.Net;
using System.Text;
using PCPorter.Collectors;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Health;
using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Posture;
using PCPorter.Core.Security;

namespace PCPorter.Reports;

/// <summary>
/// HealthReport.html: one self-contained, offline page for a non-technical owner. Order: verdict, to-do list,
/// security, moving to the new PC, hardware health, technical appendix (collapsed). No scripts, no network, prints well.
/// Every item's label comes from <see cref="Assessment"/>, the same decision the banner counts use.
/// Every value is redacted and HTML-encoded on the way out (the in-memory items are not yet redacted).
/// </summary>
public static class HealthReport
{
    public const string FileName = "HealthReport.html";

    sealed record Action(int Rank, string Title, string Why, string What);

    public static void Write(ScanJobResult r, CollectorContext ctx) =>
        File.WriteAllText(Path.Combine(r.CaseFolder, FileName), Render(r, DateTimeOffset.UtcNow), new UTF8Encoding(false));

    public static string Render(ScanJobResult r, DateTimeOffset generatedUtc)
    {
        var items = r.Run.Runs.Where(x => x.Output is not null).SelectMany(x => x.Output!.Items).ToList();
        var a = Assessment.Of(r);
        var apps = items.OfType<InstalledApp>().ToList();
        var counts = a.Counts();
        var worst = a.Worst();
        var computer = r.ScannedComputer ?? a.Profile?.ComputerName ?? "this PC";
        var actions = Actions(a);

        var (word, line) = worst switch
        {
            Level.FixThis => ("Needs attention", "A few important things need fixing. The list below says what to do, most important first."),
            Level.WorthALook => ("Worth a look", "Nothing urgent, but some items are worth checking."),
            Level.Unusual => ("Mostly fine", "A few things are unusual. Nothing needs to be done right away."),
            _ => ("Looks good", "We didn't find anything that needs your attention."),
        };
        // Never claim more than was checked.
        bool partial = r.Run.AnyFailed || r.Run.AnyPartial;
        if (worst < Level.Unusual && (partial || r.Offline))
            line = r.Offline
                ? "Nothing stood out on this drive. Some checks (antivirus state, hardware health) only work on a running PC."
                : "Nothing stood out in the parts we could check.";

        var h = new StringBuilder(64 * 1024);
        h.Append("""
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
            <meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">
            """);
        h.Append($"<title>PC health and security: {E(computer)}</title><style>{Css}</style></head><body>");
        h.Append("<a class=\"skip\" href=\"#main\">Skip to report</a>");
        h.Append("<nav class=\"toc\" aria-label=\"Sections\"><strong>Sections</strong><ol>");
        foreach (var (id, title) in new[] { ("verdict", "Summary"), ("todo", "To do"), ("security", "Security"), ("moving", "Moving to your new PC"), ("hardware", "Hardware health"), ("appendix", "Technical details") })
            h.Append($"<li><a href=\"#{id}\">{title}</a></li>");
        h.Append("</ol></nav><main id=\"main\">");

        // 1. Verdict
        h.Append($"<header id=\"verdict\" class=\"verdict {Cls(worst)}\"><div class=\"icon\" aria-hidden=\"true\">{Icon(worst)}</div><div>");
        h.Append($"<p class=\"eyebrow\">PC health and security &middot; {E(computer)}</p><h1>{word}</h1><p>{line}</p>");
        h.Append("<ul class=\"facts\">");
        h.Append($"<li><b>{counts.WorthALook}</b> worth a look</li><li><b>{counts.Unusual}</b> unusual</li>");
        var appRows = ReinstallRows(apps).Count;
        h.Append($"<li><b>{appRows}</b> app{S(appRows)} to reinstall</li>");
        h.Append($"<li>Scanned {E(generatedUtc.ToLocalTime().ToString("d MMM yyyy, HH:mm"))}{(r.Offline ? " from its drive" : "")}</li></ul>");
        if (partial)
            h.Append("<p class=\"partial\">Some checks could not finish, so parts of this report are missing. See Technical details at the end.</p>");
        h.Append("</div></header>");

        // 2. To do
        h.Append(worst switch
        {
            Level.FixThis => "<section id=\"todo\"><h2>Do these things</h2>",
            Level.WorthALook => "<section id=\"todo\"><h2>Check these things</h2>",
            _ => "<section id=\"todo\"><h2>Worth checking when you have time</h2><p class=\"muted\">Nothing here is urgent.</p>",
        });
        if (actions.Count == 0) h.Append("<p class=\"ok\">Nothing to do. Keep Windows updated and your backups running.</p>");
        else
        {
            h.Append("<ol class=\"todo\">");
            foreach (var x in actions.OrderByDescending(x => x.Rank).Take(3))
                h.Append($"<li><label><input type=\"checkbox\"> <b>{E(x.Title)}</b></label><p>{E(x.What)}</p><details><summary>Why is this here?</summary><p>{E(x.Why)}</p></details></li>");
            h.Append("</ol>");
            if (actions.Count > 3) h.Append($"<p class=\"muted\">{actions.Count - 3} smaller item{S(actions.Count - 3)} are listed in the sections below.</p>");
        }
        h.Append("</section>");

        // 3. Security
        h.Append("<section id=\"security\"><h2>Security</h2><h3>Antivirus</h3>");
        if (a.ActiveAntivirus.Count > 0)
            foreach (var av in a.ActiveAntivirus)
                h.Append(Row(Level.Ok, av.Vendor, av.IsMicrosoft == true
                    ? "Protected by Microsoft Defender, which is built into Windows. Your new PC has it already."
                    : $"Protected by {av.Vendor}." + (av.AccountUrl is { } u ? $" On your new PC, sign in at {u} to install it again." : " On your new PC, install it again from the maker's website."),
                    av.VendorNote));
        else if (a.NoAntivirus)
            h.Append(Row(Level.FixThis, "No active antivirus", "We couldn't find active antivirus. Windows Security is free and built in. Turn it on in Settings.", null));
        else if (a.Antivirus.Count > 0)
            foreach (var av in a.Antivirus) h.Append(Row(Level.Note, av.Vendor, $"{av.Vendor} is installed on this drive. On your new PC, install it again from the maker's website.", av.VendorNote));
        else
            h.Append(Row(Level.Note, "Antivirus", r.Offline ? "We can't tell which antivirus was running from a drive alone." : "We couldn't check the antivirus.", null));
        foreach (var other in a.Antivirus.Where(x => !a.ActiveAntivirus.Contains(x) && a.AntivirusKnown && x.State is not null and not Collectors.Security.WscState.On))
            h.Append(Row(Level.Note, other.Vendor, a.NoAntivirus
                ? $"{other.Vendor} is installed but is not protecting this PC ({other.Status ?? "off"}). Renew it, or rely on Windows Security instead."
                : $"Installed but not the active protection ({other.Status ?? "off"}). This is normal when another product is in charge.", null));

        h.Append("<h3>Windows protections</h3>");
        foreach (var p in a.Posture.OrderByDescending(a.LevelOf).ThenByDescending(p => p.Severity))
        {
            var lv = a.LevelOf(p);
            h.Append(Row(lv, p.Title, p.Finding, lv >= Level.Unusual ? p.Advice : null,
                p.Status switch { PostureStatus.Unknown => "Unknown", PostureStatus.NotApplicable => "Not needed", _ => null }));
        }
        if (a.Posture.Count == 0) h.Append("<p class=\"muted\">The settings check did not run.</p>");

        h.Append("<h3>Programs that start with Windows</h3>");
        AppendStartup(h, a);
        h.Append("</section>");

        // 4. Moving
        h.Append("<section id=\"moving\"><h2>Moving to your new PC</h2>");
        var reinstall = ReinstallRows(apps);
        int withSource = reinstall.Count(x => x.App.WingetId is not null || x.App.Kind == AppKind.Store || x.App.ChocoId is not null || x.App.ScoopId is not null);
        if (reinstall.Count == 0)
            h.Append(a.Ran.Contains("apps") ? "<p class=\"muted\">No apps to reinstall were found.</p>" : "<p class=\"muted\">The installed-apps check did not run.</p>");
        else
        {
            h.Append($"<p>{reinstall.Count} app{S(reinstall.Count)} to install again on the new PC. {withSource} can be installed automatically; the rest need a download from the maker's website.</p>");
            h.Append("<details open><summary>App list</summary><table><thead><tr><th scope=\"col\">App</th><th scope=\"col\">Maker</th><th scope=\"col\">Version</th><th scope=\"col\">How to get it</th></tr></thead><tbody>");
            foreach (var (app, copies) in reinstall)
                h.Append($"<tr><td>{E(app.Name)}</td><td>{E(app.Publisher)}</td><td>{E(app.Version)}{(copies > 1 ? $" <span class=\"muted\">({copies} versions installed)</span>" : "")}</td><td>{HowToGet(app)}</td></tr>");
            h.Append("</tbody></table></details>");
        }
        h.Append("<p class=\"muted\">Programs are installed fresh from their makers, never copied, so nothing harmful comes along. Scan your new PC too to compare the two side by side.</p></section>");

        // 5. Hardware
        h.Append("<section id=\"hardware\"><h2>Hardware health</h2>");
        AppendHardware(h, a.Profile);
        h.Append("</section>");

        // 6. Appendix
        h.Append("<section id=\"appendix\"><h2>Technical details</h2><details><summary>Show technical details</summary>");
        h.Append("<h3>Checks that ran</h3><table><thead><tr><th scope=\"col\">Check</th><th scope=\"col\">Result</th><th scope=\"col\">Found</th><th scope=\"col\">Time</th><th scope=\"col\">Note</th></tr></thead><tbody>");
        foreach (var x in r.Run.Runs)
            h.Append($"<tr><td>{E(x.Collector)}</td><td>{E(x.Status.ToString())}</td><td>{x.Items}</td><td class=\"time\">{x.Ms / 1000.0:0.0} s</td><td>{E(x.Message)}</td></tr>");
        h.Append("</tbody></table>");
        if (r.Warnings.Count + r.SourceNotes.Count > 0)
        {
            h.Append("<h3>Notes</h3><ul>");
            foreach (var w in r.Warnings.Concat(r.SourceNotes)) h.Append($"<li>{E(w)}</li>");
            h.Append("</ul>");
        }
        if (a.Posture.Count > 0)
        {
            h.Append("<h3>Settings evidence</h3><table><tbody>");
            foreach (var p in a.Posture) h.Append($"<tr><th scope=\"row\">{E(p.Title)}</th><td><code>{E(p.Evidence)}</code></td></tr>");
            h.Append("</tbody></table>");
        }
        if (a.Profile is { } profile)
        {
            h.Append("<h3>PC details</h3><table><tbody>");
            void Kv(string k, object? v) { if (v is not null) h.Append($"<tr><th scope=\"row\">{k}</th><td>{E(v.ToString())}</td></tr>"); }
            Kv("Windows", $"{profile.ProductName} {profile.DisplayVersion} (build {profile.Build}.{profile.Ubr})");
            Kv("Edition", profile.EditionId); Kv("Architecture", profile.Architecture); Kv("Processor", profile.Processor);
            Kv("Maker / model", profile.Manufacturer is null ? null : $"{profile.Manufacturer} {profile.Model}");
            Kv("TPM version", profile.TpmVersion); Kv("Activation channel", profile.ActivationChannel);
            Kv("Last feature update", profile.LastFeatureUpdate?.ToString("d MMM yyyy")); Kv("Windows first installed", profile.OriginalInstall?.ToString("d MMM yyyy"));
            foreach (var g in profile.VideoControllers ?? []) Kv("Graphics driver", $"{g.Name} {g.DriverVersion}");
            foreach (var (k, v) in profile.Unknown) Kv("Not read: " + E(k), v);
            h.Append("</tbody></table>");
        }
        h.Append($"<p class=\"muted scan-id\">Scan {E(r.ScanId)}. The full data is in the case folder (case.db and the scan folder).</p></details></section>");

        h.Append("</main><footer>Read-only scan. Nothing was changed or sent anywhere. Made by PCPorter.</footer></body></html>");
        return h.ToString();
    }

    /// <summary>One row per app to reinstall: several installed versions of the same app (same name and maker) count once.</summary>
    public static List<(InstalledApp App, int Copies)> ReinstallRows(IEnumerable<InstalledApp> apps) =>
        apps.Where(a => a.ReinstallCandidate && !a.Hidden)
            .GroupBy(a => (Name: a.Name.Trim().ToLowerInvariant(), Pub: a.Publisher?.Trim().ToLowerInvariant()))
            .Select(g => (App: g.OrderByDescending(a => a.WingetId is not null).ThenByDescending(a => Version.TryParse(a.Version, out var v) ? v : null).First(), Copies: g.Count()))
            .OrderBy(x => x.App.Name, StringComparer.OrdinalIgnoreCase).ToList();

    static List<Action> Actions(Assessment a)
    {
        var list = new List<Action>();
        if (a.NoAntivirus)
            list.Add(new(100, "Turn on antivirus", "No antivirus reported itself as active.", "Open Settings > Privacy & security > Windows Security and turn on Virus & threat protection."));
        foreach (var d in a.Profile?.PhysicalDisks?.Where(Assessment.DiskNeedsCare) ?? [])
            list.Add(new(95, $"Back up now: {d.Name ?? "a drive"} is wearing out", DiskLine(d), "Copy anything important off this PC today. If it gets worse, replace the drive."));
        foreach (var p in a.Posture.Where(p => a.LevelOf(p) >= Level.Unusual   // a summary of rows listed one by one is not a to-do
            && (p.Status == PostureStatus.Risk || p.Status == PostureStatus.Attention && p.Severity > PostureSeverity.Info)))   // Info = "no action needed"
            list.Add(new((p.Status == PostureStatus.Risk ? 60 : 20) + (int)p.Severity * 5, p.Title, p.Finding, p.Advice));
        foreach (var group in a.Startup.Where(s => Assessment.OfStartup(s) == Level.WorthALook).GroupBy(s => s.Name))
            list.Add(new(55, $"Check \"{group.Key}\"", group.First().Reason,
                $"{group.Key} starts with Windows and we couldn't confirm who made it. This is often harmless. If you don't recognize it, look it up or ask someone you trust before removing it."));
        if (a.Profile?.Crashes is { } c && Assessment.OfCrashes(c) == Level.WorthALook)
            list.Add(new(40, "Frequent crashes", $"{c.BugChecks90Days} blue-screen crashes in the last 90 days.", "Install Windows and driver updates. If crashes continue, test the memory and drives."));
        return list;
    }

    static void AppendStartup(StringBuilder h, Assessment a)
    {
        foreach (var s in a.Startup.Where(s => Assessment.OfStartup(s) == Level.WorthALook))
            h.Append(Row(Level.WorthALook, s.Name, s.SignatureStatus == SignatureStatus.FileMissing
                ? "Leftover entry from an uninstalled program. Harmless."
                : $"{s.Name} starts with Windows and we couldn't confirm who made it. This is often harmless. If you don't recognize it, look it up or ask someone you trust before removing it.",
                $"{s.Reason} Found in {s.Location}: {s.Command}"));
        var unusual = a.Startup.Where(s => Assessment.OfStartup(s) == Level.Unusual).ToList();
        foreach (var g in unusual.GroupBy(s => s.Signer ?? "an unknown maker"))
        {
            // The summary line is not a label: each item inside carries its own "Unusual" label (and is counted once).
            h.Append($"<details class=\"group\"><summary>{g.Count()} unusual item{S(g.Count())} from {E(g.Key)}</summary>");
            foreach (var s in g)
                h.Append(Row(Level.Unusual, s.Name, s.Disabled
                    ? $"{s.Name} is turned off, so it does not start. It was flagged because: {s.Reason}"
                    : s.SignatureStatus == SignatureStatus.FileMissing
                        ? "Leftover entry from an uninstalled program. Harmless."
                        : $"{s.Name} is set up in an uncommon way, but it comes from {s.Signer ?? "a known maker"}. No action needed unless you have problems.",
                    $"{s.Reason} Found in {s.Location}: {s.Command}"));
            h.Append("</details>");
        }
        var normal = a.Startup.Count(s => Assessment.OfStartup(s) == Level.Ok) + a.HiddenStartup;
        if (normal > 0)
            h.Append(Row(Level.Ok, "Everything else", $"{normal} startup item{S(normal)} {(normal == 1 ? "is" : "are")} from known publishers or part of Windows. Nothing to do.", null, "Normal"));
        else if (a.Startup.Count == 0)
            h.Append(a.Ran.Contains("persistence") ? "<p class=\"muted\">No startup programs were found.</p>" : "<p class=\"muted\">The startup check did not run.</p>");
    }

    static void AppendHardware(StringBuilder h, PcProfile? p)
    {
        if (p is null) { h.Append("<p class=\"muted\">The hardware check did not run.</p>"); return; }
        var facts = new List<string>();
        if (p.RamBytes is { } ram) facts.Add($"{Math.Round(ram / 1073741824.0)} GB memory");
        if (p.LogicalProcessors is { } lp) facts.Add($"{lp} processor threads");
        if (p.Architecture is { } arch) facts.Add(arch);
        if (facts.Count > 0) h.Append($"<p>{E(string.Join(" · ", facts))}</p>");

        h.Append("<h3>Drives</h3>");
        foreach (var d in p.PhysicalDisks ?? [])
            h.Append(Row(Assessment.OfDisk(d), $"{d.Name ?? "Drive"} ({Gb(d.SizeBytes)}{(d.MediaType is { } m ? ", " + m : "")})", DiskLine(d), null));
        foreach (var l in p.LogicalDisks ?? [])
            if (l.SizeBytes is > 0 && l.FreeBytes is { } free)
            {
                var pct = free * 100.0 / l.SizeBytes.Value;
                h.Append(Row(Assessment.OfFreeSpace(pct), $"Drive {l.Drive}", $"{Gb(free)} free of {Gb(l.SizeBytes)} ({pct:0}% free).", null));
            }
        if (p.PhysicalDisks is null && p.LogicalDisks is null) h.Append("<p class=\"muted\">Drive health can only be read on the running PC.</p>");

        foreach (var b in p.Batteries ?? [])
            if (b.HealthPercent is { } hp)
                h.Append(Row(Assessment.OfBattery(hp), "Battery", $"Holds {hp}% of its original charge." + (b.CycleCount is { } cc ? $" Charged about {cc} times." : ""), null));

        if (p.Crashes is { } c)
        {
            var n = c.BugChecks90Days;
            var u = c.UnexpectedShutdowns ?? 0;
            h.Append(Row(Assessment.OfCrashes(c), "Crashes",
                n + u == 0 ? "No crashes or unexpected restarts in the last 90 days."
                : $"{n} blue-screen crash{(n == 1 ? "" : "es")} and {u} unexpected restart{S(u)} in the last 90 days.", null));
        }
        foreach (var d in p.ProblemDevices ?? [])
        {
            if (Assessment.OfDevice(d) is not { } lv) continue;   // turned off on purpose in Device Manager: not a fault
            var name = string.IsNullOrWhiteSpace(d.Name) || d.Name.StartsWith('(') ? "A device without a name" : d.Name;
            var what = d.ErrorCode switch
            {
                28 => "has no driver installed",
                10 => "can't start",
                1 or 18 or 31 or 39 => "has a driver problem",
                24 or 45 => "is not connected right now",
                43 => "reported a problem and was stopped by Windows",
                _ => "isn't working properly",
            };
            h.Append(Row(lv, name, $"{name} {what}. This usually doesn't matter for moving; check it on the new PC if you use it.",
                $"Device Manager error code {d.ErrorCode}."));
        }
        if (p.TpmPresent == false || (p.TpmVersion is { } tv && !tv.StartsWith("2.", StringComparison.Ordinal)))
            h.Append(Row(Level.Note, "Security chip (TPM)", "TPM 2.0 is not turned on. This is a setting, not broken hardware. It can be turned on in the startup menu (BIOS).", null));
        if (p.SecureBoot == false)
            h.Append(Row(Level.Note, "Secure Boot", "Secure Boot is off. This is a setting, not broken hardware. It can be turned on in the startup menu (BIOS).", null));
        if (p.Activated == false)
            h.Append(Row(Level.Note, "Windows activation", "Windows isn't activated. Your new PC will have its own license.", null));
    }

    static string DiskLine(PhysicalDiskInfo d)
    {
        if (d.Health is { } hs && !hs.Equals("Healthy", StringComparison.OrdinalIgnoreCase))
            return "This drive reports a problem with its health. Back up now. If it gets worse, replace it.";
        if (d.WearPercent is int used and >= 90)
            return $"This drive has used about {Math.Min(used, 100)}% of its rated life. Back up regularly and plan to replace it.";
        var s = d.WearPercent is { } w ? $"Healthy (about {100 - w}% of rated life left)." : d.Health is not null ? "Healthy." : "Health not reported by this drive.";
        if (d.TemperatureC is >= 60) s += $" Running hot ({d.TemperatureC} °C).";
        return s;
    }

    static string HowToGet(InstalledApp a)
    {
        if (a.Kind == AppKind.Store) return "Microsoft Store";
        if (a.WingetId is { } w) return $"Automatic <code>{E(w)}</code>";
        if (a.ChocoId is { } c) return $"Automatic (Chocolatey <code>{E(c)}</code>)";
        if (a.ScoopId is { } s) return $"Automatic (Scoop <code>{E(s)}</code>)";
        var link = Http(a.UrlInfoAbout) ?? Http(a.HelpLink);
        return link is null ? "Maker's website" : $"Download from <span class=\"url\">{E(link)}</span>";
    }

    /// <summary>Links are shown as text, not anchors: a value from the scanned PC is never made clickable.</summary>
    static string? Http(string? u) => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme is "https" or "http" ? x.GetLeftPart(UriPartial.Path) : null;

    /// <summary>
    /// One finding row. The label always comes from the level; <paramref name="okOrNoteLabel"/> may only rename
    /// an OK or Note label ("Normal", "Unknown"), never invent a counted one.
    /// </summary>
    static string Row(Level level, string title, string text, string? detail, string? okOrNoteLabel = null)
    {
        var label = level <= Level.Note && okOrNoteLabel is not null ? okOrNoteLabel : Assessment.Label(level);
        var sb = new StringBuilder($"<div class=\"row {Cls(level)}\" data-level=\"{level}\"><span class=\"chip {Cls(level)}\">{E(label)}</span><div><b>{E(title)}</b><p>{E(text)}</p>");
        if (!string.IsNullOrWhiteSpace(detail)) sb.Append($"<details><summary>Why is this here?</summary><p>{E(detail)}</p></details>");
        return sb.Append("</div></div>").ToString();
    }

    static string Cls(Level l) => l switch { Level.Ok => "good", Level.Note or Level.Unusual => "note", Level.WorthALook => "look", _ => "bad" };
    static string Icon(Level l) => l switch { Level.Ok or Level.Note => "&#10003;", Level.FixThis => "!", _ => "i" };
    static string S(int n) => n == 1 ? "" : "s";
    static string Gb(long? b) => b is null ? "?" : b >= 1_000_000_000_000 ? $"{b / 1e12:0.#} TB" : $"{b / 1e9:0} GB";

    /// <summary>Redact, then HTML-encode. Everything from the scanned PC goes through here.</summary>
    static string E(string? s) => s is null ? "" : WebUtility.HtmlEncode(Redactor.Redact(s));

    const string Css = """
        :root{--bg:#fff;--fg:#1b1b1b;--muted:#5c5c5c;--line:#d6d6d6;--card:#f7f7f7;--good:#0f7b0f;--note:#005fb8;--look:#9d5d00;--bad:#c42b1c;color-scheme:light dark}
        @media (prefers-color-scheme:dark){:root{--bg:#1c1c1c;--fg:#f3f3f3;--muted:#b5b5b5;--line:#3d3d3d;--card:#262626;--good:#6ccb5f;--note:#60cdff;--look:#fce100;--bad:#ff99a4}}
        *{box-sizing:border-box}body{margin:0;font:16px/1.55 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg);display:grid;grid-template-columns:220px minmax(0,900px);gap:32px;padding:32px}
        .skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--bg);padding:8px}
        .toc{position:sticky;top:32px;align-self:start;font-size:14px}.toc ol{padding-left:18px}.toc a{color:var(--fg)}
        h1{font-size:32px;margin:0 0 4px}h2{font-size:22px;margin:40px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:17px;margin:24px 0 8px}
        .verdict{display:flex;gap:20px;padding:24px;border-radius:12px;background:var(--card);border-left:8px solid currentColor}
        .verdict>div:last-child{color:var(--fg)}.verdict .icon{font-size:30px;font-weight:700;width:52px;height:52px;border-radius:50%;border:3px solid currentColor;display:grid;place-items:center;flex:none}
        .eyebrow{margin:0;color:var(--muted);font-size:14px}.facts{display:flex;flex-wrap:wrap;gap:8px 24px;padding:0;list-style:none;margin:12px 0 0}
        .good{color:var(--good)}.note{color:var(--note)}.look{color:var(--look)}.bad{color:var(--bad)}
        .row{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--line)}.row>div{color:var(--fg);flex:1}.row p{margin:2px 0}
        .chip{flex:none;font-size:12px;font-weight:600;border:1.5px solid currentColor;border-radius:99px;padding:1px 10px;margin-top:3px;white-space:nowrap}
        details summary{cursor:pointer;color:var(--note)}details p{color:var(--muted)}.group{margin:8px 0}.group summary{color:var(--fg)}
        .todo{padding-left:22px}.todo li{margin-bottom:14px}.todo p{margin:2px 0}.ok{color:var(--good)}.muted{color:var(--muted)}.partial{color:var(--look)}
        table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}code{font-size:13px;word-break:break-all}.url{word-break:break-all}
        footer{grid-column:2;color:var(--muted);font-size:14px;margin:40px 0;border-top:1px solid var(--line);padding-top:12px}
        @media (max-width:900px){body{grid-template-columns:1fr;padding:16px}.toc{position:static}footer{grid-column:1}}
        @media print{body{display:block;background:#fff;color:#000;padding:0}.toc,.skip{display:none}section{break-before:page}.verdict{background:#fff}details::details-content{content-visibility:visible;display:block}details summary{display:none}}
        """;
}
