using System.Buffers.Binary;
using System.Text.RegularExpressions;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Health;

/// <summary>PC profile facts that live in the SOFTWARE and SYSTEM hives (works live and offline).</summary>
public static class HiveProfile
{
    public const string DisplayClass = "{4d36e968-e325-11ce-bfc1-08002be10318}";

    public static PcProfile Read(ISystemSource src, IList<string> warnings)
    {
        IRegKey? software = null, system = null;
        string? ccs = null;
        try { software = src.OpenHive(Hive.Software); } catch (Exception e) { warnings.Add($"Profile: SOFTWARE hive unreadable: {e.Message}"); }
        try { system = src.OpenHive(Hive.System); ccs = src.CurrentControlSet(); } catch (Exception e) { warnings.Add($"Profile: SYSTEM hive unreadable: {e.Message}"); }
        return Read(software, system, ccs, warnings);
    }

    public static PcProfile Read(IRegKey? software, IRegKey? system, string? ccs, IList<string> warnings)
    {
        var p = new PcProfile();
        p = Section(p, warnings, "Windows version", () => Os(p, software));
        p = Section(p, warnings, "install history", () => Installs(p, system));
        p = Section(p, warnings, "system settings", () => SystemFacts(p, software, system, ccs));
        p = Section(p, warnings, "graphics memory", () => p with { Gpus = Gpus(system, ccs) });
        return p;
    }

    static PcProfile Section(PcProfile p, IList<string> warnings, string what, Func<PcProfile> f)
    {
        try { return f(); }
        catch (Exception e) { warnings.Add($"Profile: could not read {what}: {e.Message}"); return p; }
    }

    static PcProfile Os(PcProfile p, IRegKey? software)
    {
        var cv = software?.Open(@"Microsoft\Windows NT\CurrentVersion");
        if (cv is null) return p;
        var productName = cv.GetString("ProductName");
        var editionId = cv.GetString("EditionID");
        int? build = int.TryParse(cv.GetString("CurrentBuildNumber") ?? cv.GetString("CurrentBuild"), out var b) ? b : null;
        var ubr = cv.GetNumber("UBR");
        long? installDate = cv.GetNumber("InstallDate");
        return p with
        {
            ProductName = productName,
            EditionId = editionId,
            IsHomeEdition = editionId is null ? null : IsHome(editionId),
            OsName = OsName(productName, editionId, build),
            DisplayVersion = cv.GetString("DisplayVersion") ?? cv.GetString("ReleaseId"),
            Build = build,
            Ubr = ubr is { } u and >= 0 and <= int.MaxValue ? (int)u : null,
            LastFeatureUpdate = installDate is > 0 ? DateTimeOffset.FromUnixTimeSeconds(installDate.Value) : null,
        };
    }

    public static bool IsHome(string? editionId) => editionId?.StartsWith("Core", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// The registry ProductName still says "Windows 10" on Windows 11, so build >= 22000 => "Windows 11 " + edition.
    /// EditionID Core* => Home.
    /// </summary>
    public static string? OsName(string? productName, string? editionId, int? build)
    {
        if (build is null or < 22000) return productName;
        string edition;
        if (IsHome(editionId)) edition = "Home";
        else if (productName is not null)
        {
            var m = Regex.Match(productName, @"^\s*(Microsoft\s+)?Windows\s+(10|11)\s*(?<ed>.*)$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
            edition = m.Success ? m.Groups["ed"].Value.Trim() : productName.Trim();
        }
        else edition = editionId ?? "";
        return ("Windows 11 " + edition).Trim();
    }

    static PcProfile Installs(PcProfile p, IRegKey? system)
    {
        DateTimeOffset? oldest = null;
        foreach (var k in system?.Open("Setup")?.SubKeys ?? [])
        {
            if (!k.Name.StartsWith("Source OS", StringComparison.OrdinalIgnoreCase)) continue;
            if (k.GetNumber("InstallDate") is { } s && s > 0)
            {
                var t = DateTimeOffset.FromUnixTimeSeconds(s);
                if (oldest is null || t < oldest) oldest = t;
            }
        }
        var original = oldest is { } o && (p.LastFeatureUpdate is null || o < p.LastFeatureUpdate) ? o : p.LastFeatureUpdate;
        return p with { OriginalInstall = original };
    }

    public static string? NormalizeArch(string? processorArchitecture) => processorArchitecture?.Trim().ToUpperInvariant() switch
    {
        null or "" => null,
        "AMD64" or "X64" => "x64",
        "ARM64" => "arm64",
        "X86" => "x86",
        var other => other.ToLowerInvariant(),
    };

    static PcProfile SystemFacts(PcProfile p, IRegKey? software, IRegKey? system, string? ccs)
    {
        var cs = ccs is null ? null : system?.Open(ccs);
        var deny = cs?.Open(@"Control\Terminal Server")?.GetNumber("fDenyTSConnections");
        var vmms = cs?.Open(@"Services\vmms");
        var secureBoot = cs?.Open(@"Control\SecureBoot\State")?.GetNumber("UEFISecureBootEnabled");
        return p with
        {
            Architecture = NormalizeArch(cs?.Open(@"Control\Session Manager\Environment")?.GetString("PROCESSOR_ARCHITECTURE")),
            ComputerName = cs?.Open(@"Control\ComputerName\ComputerName")?.GetString("ComputerName"),
            MachineGuid = software?.Open(@"Microsoft\Cryptography")?.GetString("MachineGuid"),
            SecureBoot = secureBoot is null ? null : secureBoot == 1,
            RdpEnabled = deny is null ? null : deny == 0,
            HyperVEnabled = cs is null ? null : vmms is not null && vmms.GetNumber("Start") != 4,
            DomainJoined = JoinState.DomainJoinedFromHive(system, ccs),
            EntraJoined = JoinState.EntraJoinedFromHive(software, system, ccs),
        };
    }

    /// <summary>Display adapters: numeric subkeys of the display class; qwMemorySize, else MemorySize (binary or DWORD).</summary>
    public static IReadOnlyList<GpuInfo>? Gpus(IRegKey? system, string? ccs)
    {
        var cls = ccs is null ? null : system?.Open($@"{ccs}\Control\Class\{DisplayClass}");
        if (cls is null) return null;
        var list = new List<GpuInfo>();
        foreach (var k in cls.SubKeys.OrderBy(k => k.Name, StringComparer.Ordinal))
        {
            if (k.Name.Length == 0 || !k.Name.All(char.IsAsciiDigit)) continue;
            var name = k.GetString("DriverDesc") ?? k.GetString("HardwareInformation.AdapterString");
            if (name is null) continue;
            var vram = Size(k.GetRaw("HardwareInformation.qwMemorySize")) ?? Size(k.GetRaw("HardwareInformation.MemorySize"));
            list.Add(new GpuInfo(name, vram));
        }
        // Remote/indirect display adapters get a new numbered key per session: report each distinct adapter once.
        return list.Distinct().ToList();
    }

    static long? Size((RegType Type, byte[] Raw)? v)
    {
        if (v is not { } x) return null;
        long? n = x.Raw.Length switch
        {
            8 when x.Type is RegType.QWord or RegType.Binary => unchecked((long)BinaryPrimitives.ReadUInt64LittleEndian(x.Raw)),
            4 when x.Type is RegType.DWord or RegType.Binary => BinaryPrimitives.ReadUInt32LittleEndian(x.Raw),
            _ => null,
        };
        return n is > 0 ? n : null;
    }
}
