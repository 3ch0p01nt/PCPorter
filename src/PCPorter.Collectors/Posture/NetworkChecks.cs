using System.Net;
using System.Text;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Posture;

/// <summary>Browser policies, proxy, DNS, hosts file and open ports.</summary>
public static class NetworkChecks
{
    static readonly string[] OfficialStoreHosts = ["clients2.google.com", "edge.microsoft.com", "addons.mozilla.org"];
    static readonly (string Browser, string Path)[] PolicyRoots =
    [
        ("Chrome", @"Policies\Google\Chrome"),
        ("Edge", @"Policies\Microsoft\Edge"),
    ];

    // 9. Force-installed browser extensions
    internal static IEnumerable<PostureCheck> BrowserExtensions(PostureScan s)
    {
        const string id = PostureIds.BrowserExtensions, title = "Forced browser extensions";
        var found = new List<(string Browser, string Scope, string ExtId, string? Url, bool Official)>();
        void Read(IRegKey? root, string scope, string prefix)
        {
            foreach (var (browser, path) in PolicyRoots)
            {
                PostureScan.With(root, prefix + path + @"\ExtensionInstallForcelist", k =>
                {
                    if (k is null) return 0;
                    foreach (var name in k.ValueNames)
                    {
                        var data = k.GetString(name)?.Trim();
                        if (string.IsNullOrEmpty(data)) continue;
                        var semi = data.IndexOf(';');
                        var extId = (semi < 0 ? data : data[..semi]).Trim();
                        var url = semi < 0 ? null : data[(semi + 1)..].Trim();
                        found.Add((browser, scope, extId, string.IsNullOrEmpty(url) ? null : url, IsOfficial(url)));
                    }
                    return 0;
                });
                // ExtensionSettings: one JSON value that can also force extensions in ("installation_mode": "force_installed").
                PostureScan.With(root, prefix + path, k =>
                {
                    if (k?.GetString("ExtensionSettings") is { Length: > 0 } json)
                        foreach (var (extId, _, url) in Persistence.RegistryPersistence.ForcedInSettings(json))
                            found.Add((browser, scope, extId, url, IsOfficial(url)));
                    return 0;
                });
            }
            // Firefox: Policies\Mozilla\Firefox\Extensions\Install lists extension addresses or files.
            PostureScan.With(root, prefix + @"Policies\Mozilla\Firefox\Extensions\Install", k =>
            {
                if (k is null) return 0;
                foreach (var name in k.ValueNames)
                    if (k.GetString(name)?.Trim() is { Length: > 0 } v)
                        found.Add(("Firefox", scope, v, v, IsOfficial(v)));
                return 0;
            });
        }
        Read(s.Software, "machine", "");
        foreach (var (user, hive) in s.UserHives) Read(hive, "user " + user.UserName, @"Software\");

        var results = new List<PostureCheck>();
        foreach (var e in found.Where(f => !f.Official))
            results.Add(Make.Check($"{PostureIds.BrowserExtensionPrefix}{e.Browser.ToLowerInvariant()}:{Slug(e.Scope)}:{e.ExtId}",
                $"Forced {e.Browser} extension", PostureStatus.Attention, PostureSeverity.Medium,
                $"A {e.Browser} extension is installed by policy from outside the official store, and cannot be removed in the browser.",
                "If this is a work PC, your IT team may have added it. If not, ask someone technical to check it: unwanted forced extensions are a common sign of adware.",
                $"{e.Scope}: {e.ExtId} from {e.Url}"));

        var evidence = found.Count == 0 ? "No extensions forced by Chrome, Edge or Firefox policies."
            : string.Join("; ", found.Select(f => $"{f.Browser} {f.Scope}: {f.ExtId} ({(f.Official ? "official store" : f.Url)})"));
        if (s.Software is null && s.UserHives.Count == 0)
            results.Insert(0, Make.Unknown(id, title, "We could not read the browser policies.", evidence));
        else if (results.Count > 0)
            results.Insert(0, Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                $"{results.Count} browser extension(s) are forced on from outside the official stores.",
                "Each one is listed below. If you did not set this up and this is not a work PC, have them checked.", evidence));
        else if (found.Count > 0)
            results.Insert(0, Make.Good(id, title, $"{found.Count} browser extension(s) are installed by policy, all from the official stores (usually set by work or school).", evidence));
        else results.Insert(0, Make.Good(id, title, "No browser extensions are forced on by policy.", evidence));
        return results;
    }

    static bool IsOfficial(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;            // no update URL: the browser uses its own store
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return false;
        return OfficialStoreHosts.Any(h => string.Equals(u.Host, h, StringComparison.OrdinalIgnoreCase));
    }

    static string Slug(string scope) => scope.Replace(' ', '-').ToLowerInvariant();

    // 10a. Proxy / PAC
    internal static PostureCheck Proxy(PostureScan s)
    {
        const string id = PostureIds.Proxy, title = "Web proxy";
        if (s.UserHives.Count == 0) return Make.Unknown(id, title, "We could not read any user's internet settings.", $"{s.UsersWithoutHive} user hive(s) unreadable.");
        var ev = new List<string>();
        var users = new List<string>();
        foreach (var (user, hive) in s.UserHives)
        {
            var (enable, server, pac) = PostureScan.With(hive, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                k => (k?.GetNumber("ProxyEnable"), k?.GetString("ProxyServer"), k?.GetString("AutoConfigURL")));
            bool on = enable == 1 || !string.IsNullOrWhiteSpace(pac);
            ev.Add($"{user.UserName}: ProxyEnable={Make.Num(enable)} ProxyServer={server ?? "(not set)"} AutoConfigURL={pac ?? "(not set)"}");
            if (on) users.Add(user.UserName);
        }
        var evidence = string.Join("; ", ev);
        if (users.Count == 0) return Make.Good(id, title, "Web traffic goes straight to the internet (no proxy is set).", evidence);
        return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"Web traffic for {string.Join(", ", users)} is sent through a proxy or a proxy script.",
            "Work and school networks often use this. If you did not set it up, check Settings > Network & internet > Proxy: an unexpected proxy can watch your browsing.", evidence);
    }

    static readonly HashSet<string> WellKnownResolvers = new(StringComparer.OrdinalIgnoreCase)
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
    };

    // 10b. Manually set DNS servers
    internal static PostureCheck Dns(PostureScan s)
    {
        const string id = PostureIds.Dns, title = "DNS servers";
        if (s.ControlSet is null) return Make.Unknown(id, title, "We could not read the network settings.", "SYSTEM hive or control set missing.");
        var servers = new List<string>();
        foreach (var tcpip in new[] { @"Services\Tcpip\Parameters", @"Services\Tcpip6\Parameters" })
        {
            PostureScan.With(s.ControlSet, tcpip, p => { if (p is not null) servers.AddRange(Split(p.GetString("NameServer"))); return 0; });
            PostureScan.With(s.ControlSet, tcpip + @"\Interfaces", ifs =>
            {
                if (ifs is null) return 0;
                foreach (var i in ifs.SubKeys)
                    try { servers.AddRange(Split(i.GetString("NameServer"))); } finally { PostureScan.Dispose(i); }
                return 0;
            });
        }
        var distinct = servers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var unusual = distinct.Where(x => !WellKnownResolvers.Contains(x) && !IsPrivate(x)).ToList();
        var evidence = distinct.Count == 0 ? "No manually set NameServer values (DNS comes from the network automatically)."
            : $"Manual DNS servers: {string.Join(", ", distinct)}";
        if (distinct.Count == 0) return Make.Good(id, title, "DNS (the internet's address book) is provided automatically by the network.", evidence);
        if (unusual.Count == 0) return Make.Good(id, title, "DNS servers are set by hand, to well-known public services or your local network.", evidence);
        return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
            $"DNS (the internet's address book) is set by hand to servers we do not recognize ({string.Join(", ", unusual)}).",
            "If you or your IT team did not choose these, set DNS back to automatic in Settings > Network & internet > your connection > DNS server assignment.", evidence);
    }

    static IEnumerable<string> Split(string? v) =>
        string.IsNullOrWhiteSpace(v) ? [] : v.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    static bool IsPrivate(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
    }

    public const string DefaultHostsFolder = @"%SystemRoot%\System32\drivers\etc";
    const long MaxHostsBytes = 8 * 1024 * 1024;

    // 10c. Hosts file and its location
    internal static PostureCheck HostsFile(PostureScan s)
    {
        const string id = PostureIds.HostsFile, title = "Hosts file";
        var dbPath = PostureScan.With(s.ControlSet, @"Services\Tcpip\Parameters", k => k?.GetString("DataBasePath"));
        bool movedFolder = dbPath is not null && !string.Equals(
            SourcePaths.Expand(dbPath, s.Source.OriginalSystemDrive).TrimEnd('\\'),
            SourcePaths.Expand(DefaultHostsFolder, s.Source.OriginalSystemDrive), StringComparison.OrdinalIgnoreCase);
        var folder = movedFolder ? dbPath! : DefaultHostsFolder;
        var mapped = s.Source.MapPath(folder.TrimEnd('\\') + @"\hosts");
        var ev = $"DataBasePath={dbPath ?? "(not set)"}{(movedFolder ? " (not the default)" : "")}";

        List<(string Ip, string Host)>? entries = null;
        if (mapped is not null && SourcePresence.IsFile(mapped))
        {
            try { entries = ReadHosts(mapped); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ev += $"; hosts unreadable ({e.GetType().Name})"; }
        }
        else ev += "; hosts file not found";

        if (movedFolder)
            return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.High,
                "Windows was told to look for its network 'hosts' list in an unusual folder.",
                "Malware sometimes does this to redirect websites. Ask someone technical to check the setting (Tcpip DataBasePath) and set it back to the default.", ev);
        if (entries is null) return Make.Unknown(id, title, "We could not read the hosts file.", ev);

        var redirects = entries.Where(e => !IsBlock(e.Ip) && !IsLocalhostName(e.Host)).ToList();
        var blocks = entries.Count - redirects.Count;
        ev += $"; {entries.Count} active line(s): {blocks} block/localhost, {redirects.Count} redirect(s)";
        if (redirects.Count > 0) ev += ": " + string.Join(", ", redirects.Take(20).Select(r => $"{r.Host} -> {r.Ip}")) + (redirects.Count > 20 ? ", ..." : "");
        if (redirects.Count > 0)
            return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                $"The hosts file sends {redirects.Count} web address(es) to specific servers instead of the normal ones.",
                "Developers and some programs add these on purpose. If you did not, ask someone technical to review the hosts file: it can be used to fake websites.", ev);
        return Make.Good(id, title, blocks > 0 ? $"The hosts file only blocks or points {blocks} name(s) at this PC (often an ad blocker)." : "The hosts file has no custom entries.", ev);
    }

    static List<(string Ip, string Host)> ReadHosts(string path)
    {
        using var fs = SourceFiles.OpenRead(path);
        using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var list = new List<(string, string)>();
        long read = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null && read < MaxHostsBytes)
        {
            read += line.Length + 2;
            var hash = line.IndexOf('#');
            var t = (hash >= 0 ? line[..hash] : line).Trim();
            if (t.Length == 0) continue;
            var parts = t.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            foreach (var host in parts.Skip(1)) list.Add((parts[0], host));
        }
        return list;
    }

    static bool IsBlock(string ip) => ip is "0.0.0.0" or "::" or "::1" or "127.0.0.1" || ip.StartsWith("127.", StringComparison.Ordinal);
    static bool IsLocalhostName(string host) => host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase);

    static readonly Dictionary<int, string> RiskyPorts = new()
    {
        [3389] = "Remote Desktop", [445] = "file sharing (SMB)", [5900] = "VNC remote control", [23] = "Telnet", [21] = "FTP",
    };

    // 14. Listening TCP ports (live only)
    internal static PostureCheck ListeningPorts(PostureScan s)
    {
        const string id = PostureIds.ListeningPorts, title = "Open network ports";
        if (!s.IsLive) return Make.LiveOnlyUnknown(id, title);
        IReadOnlyList<PortListener>? listeners;
        try { listeners = (s.Options.Listeners ?? TcpListeners.Read)(); }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { listeners = null; }
        if (listeners is null) return Make.Unknown(id, title, "We could not list the open network ports.", "GetExtendedTcpTable failed.", true);

        var open = listeners.Where(l => l.AllInterfaces).OrderBy(l => l.Port).ToList();
        var evidence = $"{listeners.Count} listening socket(s); on all interfaces: " +
            (open.Count == 0 ? "none" : string.Join(", ", open.Select(l => $"{l.Address}:{l.Port} pid {l.ProcessId} {l.ProcessName ?? "?"}")));
        var risky = open.Where(l => RiskyPorts.ContainsKey(l.Port)).Select(l => l.Port).Distinct().ToList();
        if (risky.Count > 0)
            return Make.Check(id, title, PostureStatus.Attention, PostureSeverity.Medium,
                $"This PC accepts connections from the network for: {string.Join(", ", risky.Select(p => $"{RiskyPorts[p]} (port {p})"))}.",
                "That is normal on many PCs and your router usually blocks it from the internet. Make sure the firewall is on, and turn off features you do not use.", evidence, true);
        return Make.Good(id, title, "No commonly attacked services are open to the network.", evidence, true);
    }
}
