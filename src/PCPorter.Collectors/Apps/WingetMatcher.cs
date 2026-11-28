using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;

namespace PCPorter.Collectors.Apps;

public sealed record WingetPackage(string Id, string? Version, string Source);

/// <summary>
/// Maps installed apps to winget package ids. <c>winget export</c> runs only on the live PC and only when PCPorter is
/// NOT elevated (winget.exe lives in a user-writable folder; an elevated process must never start it), as the account
/// signed in to Windows.
/// Never passes --accept-source-agreements.
/// </summary>
public static class WingetMatcher
{
    public const string Method = "ExportFallback";
    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Elevated or offline: winget's catalog file only (nothing is started). Live and not elevated: <c>winget export</c>
    /// first, then the catalog fills the gaps when it can be read. Apps left unmatched get MatchMethod "None".
    /// </summary>
    public static void Apply(CollectorContext ctx, List<InstalledApp> apps, IList<string> notes, CancellationToken ct)
    {
        bool elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        // 1. winget's own records of what it installed (per user; also works offline): exact, so they go first.
        int tracked = 0;
        foreach (var record in WingetIndex.OpenTracking(ctx.Source, notes)) tracked += record.Match(apps);
        if (tracked > 0) notes.Add($"{tracked} app(s) were installed with winget or the Store, according to winget's own records.");
        ct.ThrowIfCancellationRequested();
        // winget export describes the account it runs as; when that is not the one signed in to Windows (started with
        // another account's password) it would list the wrong person's apps, so only the catalog is used.
        bool otherAccount = InteractiveUser.Current.Differ;
        if (ctx.Source.IsLive && !elevated && !otherAccount) RunExport(ctx, apps, notes, ct);
        ct.ThrowIfCancellationRequested();
        using (var index = WingetIndex.Open(ctx.Source, out var why))
        {
            if (index is null) { if (!ctx.Source.IsLive || elevated || otherAccount) notes.Add(why!); }
            else notes.Add($"winget catalog: {index.Match(apps)} app(s) matched from {index.PackageCount:N0} known packages.");
        }
        for (int i = 0; i < apps.Count; i++)
            if (apps[i].MatchMethod is null && apps[i].Kind is not (AppKind.Store or AppKind.Portable)) apps[i] = apps[i] with { MatchMethod = "None" };
    }

    static void RunExport(CollectorContext ctx, List<InstalledApp> apps, IList<string> notes, CancellationToken ct)
    {
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "winget.exe");
        if (!File.Exists(exe)) { notes.Add("winget is not installed for this account; apps were not matched to winget packages."); return; }

        Directory.CreateDirectory(ctx.WorkFolder);
        var output = Path.Combine(ctx.WorkFolder, "winget.json");
        if (File.Exists(output)) File.Delete(output);
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            WorkingDirectory = ctx.WorkFolder,
        };
        foreach (var a in new[] { "export", "--source", "winget", "-o", output, "--include-versions", "--disable-interactivity" }) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi);
            if (p is null) { notes.Add("winget could not be started."); return; }
            p.StandardInput.Close();
            _ = p.StandardOutput.ReadToEndAsync(ct);
            _ = p.StandardError.ReadToEndAsync(ct);
            var deadline = DateTime.UtcNow + Timeout;
            while (!p.WaitForExit(250))
            {
                if (ct.IsCancellationRequested || DateTime.UtcNow > deadline)
                {
                    try { p.Kill(true); } catch (InvalidOperationException) { }
                    notes.Add(ct.IsCancellationRequested ? "winget matching was cancelled." : "winget did not finish in time; apps were not matched.");
                    return;
                }
            }
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            notes.Add($"winget could not be run ({e.GetType().Name}).");
            return;
        }
        if (!File.Exists(output)) { notes.Add("winget produced no export (it may need its source terms accepted once in a terminal)."); return; }

        var packages = ParseExport(File.ReadAllText(output));
        var matched = Match(apps, packages);
        notes.Add($"winget: {matched} of {packages.Count} exported package(s) matched to apps.");
    }

    /// <summary>Sources[].Packages[].PackageIdentifier/Version. Ids starting "ARP\" (no real package) are ignored. Never throws.</summary>
    public static List<WingetPackage> ParseExport(string json)
    {
        var list = new List<WingetPackage>();
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("Sources", out var sources) || sources.ValueKind != JsonValueKind.Array) return list;
            foreach (var s in sources.EnumerateArray())
            {
                if (s.ValueKind != JsonValueKind.Object) continue;
                var sourceName = s.TryGetProperty("SourceDetails", out var d) && d.ValueKind == JsonValueKind.Object && d.TryGetProperty("Name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : "winget";
                if (!s.TryGetProperty("Packages", out var pkgs) || pkgs.ValueKind != JsonValueKind.Array) continue;
                foreach (var p in pkgs.EnumerateArray())
                {
                    if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty("PackageIdentifier", out var idEl) || idEl.ValueKind != JsonValueKind.String) continue;
                    var id = idEl.GetString()!;
                    if (id.Length == 0 || id.StartsWith(@"ARP\", StringComparison.OrdinalIgnoreCase) || id.StartsWith(@"MSIX\", StringComparison.OrdinalIgnoreCase)) continue;
                    var ver = p.TryGetProperty("Version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                    list.Add(new WingetPackage(id, ver, sourceName));
                }
            }
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { }
        return list;
    }

    /// <summary>
    /// Matches packages to apps by normalized name: the app's match key equals the id's name part ("Git.Git" -> "git") or the
    /// whole id ("Microsoft.VisualStudioCode" -> "microsoftvisualstudiocode"); with equal versions a prefix match is also
    /// accepted. Apps already matched keep their id. Returns the number of packages matched. Unmatched apps get MatchMethod None.
    /// </summary>
    public static int Match(List<InstalledApp> apps, IReadOnlyList<WingetPackage> packages)
    {
        int matched = 0;
        var keys = apps.Select(a => AppNameNormalizer.MatchKey(a.Name)).ToList();
        foreach (var pkg in packages)
        {
            var dot = pkg.Id.IndexOf('.');
            var full = AppNameNormalizer.Squash(pkg.Id);
            var tail = dot > 0 ? AppNameNormalizer.Squash(pkg.Id[(dot + 1)..]) : full;
            bool Eligible(int i) => apps[i].WingetId is null && apps[i].Kind is not (AppKind.Store or AppKind.Portable) && keys[i].Length > 0;
            bool SameVersion(int i) => pkg.Version is not null && apps[i].Version is not null
                && (apps[i].Version == pkg.Version || apps[i].Version!.StartsWith(pkg.Version + ".", StringComparison.Ordinal) || pkg.Version.StartsWith(apps[i].Version + ".", StringComparison.Ordinal));

            var hits = Enumerable.Range(0, apps.Count).Where(i => Eligible(i) && (keys[i] == tail || keys[i] == full)).ToList();
            if (hits.Count == 0 && tail.Length >= 4)
                hits = Enumerable.Range(0, apps.Count).Where(i => Eligible(i) && SameVersion(i) && (keys[i].StartsWith(full) || keys[i].StartsWith(tail))).ToList();
            if (hits.Count > 1 && hits.Any(SameVersion)) hits = hits.Where(SameVersion).ToList();
            if (hits.Any(i => !apps[i].Hidden)) hits = hits.Where(i => !apps[i].Hidden).ToList();
            if (hits.Count == 0) continue;
            matched++;
            foreach (var i in hits) apps[i] = apps[i] with { WingetId = pkg.Id, WingetSource = pkg.Source, MatchMethod = Method };
        }
        for (int i = 0; i < apps.Count; i++)
            if (apps[i].MatchMethod is null && apps[i].Kind is not (AppKind.Store or AppKind.Portable)) apps[i] = apps[i] with { MatchMethod = "None" };
        return matched;
    }
}
