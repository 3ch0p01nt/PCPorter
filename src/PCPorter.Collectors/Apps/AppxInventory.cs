using System.Security.Principal;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

namespace PCPorter.Collectors.Apps;

/// <summary>Microsoft Store (MSIX/AppX) apps of the account signed in to Windows. Live only.</summary>
public static class AppxInventory
{
    public const string OfflineNote = "Store apps are listed only for the running PC.";

    public static List<InstalledApp> Read(ISystemSource source, IList<string> notes, IList<string> warnings)
    {
        var list = new List<InstalledApp>();
        if (!source.IsLive) { notes.Add(OfflineNote); return list; }

        // The account signed in to Windows, also when an administrator's password was typed at the UAC prompt (listing
        // another account's packages needs administrator, which PCPorter then has).
        var accounts = InteractiveUser.Current;
        var who = accounts.SignedIn;
        IEnumerable<Package> packages;
        try { packages = new PackageManager().FindPackagesForUser(accounts.Differ ? who.Sid.Value : "").ToList(); }
        catch (Exception e) { notes.Add($"Store apps could not be listed on this PC ({e.GetType().Name})."); return list; }

        var sid = who.Sid.Value;
        var userName = source.Users.FirstOrDefault(u => u.Sid == sid)?.UserName ?? who.ShortName;
        int failed = 0;
        foreach (var p in packages)
        {
            try
            {
                if (p.IsFramework || p.IsResourcePackage || p.SignatureKind == PackageSignatureKind.System) continue;
                var id = p.Id;
                var name = Safe(() => p.DisplayName);
                if (string.IsNullOrWhiteSpace(name) || name.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)) name = id.Name;
                var v = id.Version;
                var arch = id.Architecture switch
                {
                    Windows.System.ProcessorArchitecture.X64 => "x64", Windows.System.ProcessorArchitecture.X86 => "x86", Windows.System.ProcessorArchitecture.Arm64 => "arm64",
                    Windows.System.ProcessorArchitecture.Neutral => "neutral", _ => id.Architecture.ToString().ToLowerInvariant(),
                };
                var publisher = Safe(() => p.PublisherDisplayName);
                var installed = Safe(() => (DateTimeOffset?)p.InstalledDate);
                var app = InstalledApp.Create(name, $"{v.Major}.{v.Minor}.{v.Build}.{v.Revision}", publisher, arch, "User:" + userName,
                    AppKind.Store, "appx:" + id.FullName, Safe(() => p.InstalledPath),
                    installed is { Year: > 1601 } d ? DateOnly.FromDateTime(d.UtcDateTime) : null,
                    reinstallCandidate: p.SignatureKind == PackageSignatureKind.Store);
                list.Add(app with { PackageFamilyName = id.FamilyName });
            }
            catch (Exception) { failed++; }
        }
        if (failed > 0) warnings.Add($"{failed} Store app(s) could not be read.");
        if (accounts.Differ)
            notes.Add($"Store apps are listed for {who.ShortName}, the account signed in to Windows (PCPorter was started with {accounts.Process.ShortName}'s password).");
        else if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            notes.Add("Store apps are listed for the account running PCPorter.");
        return list;
    }

    static T? Safe<T>(Func<T> f) { try { return f(); } catch (Exception) { return default; } }
}
