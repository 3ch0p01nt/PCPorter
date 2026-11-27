using System.Text.RegularExpressions;

namespace PCPorter.Collectors.Security;

/// <param name="Id">Stable vendor id; used as the AV item key.</param>
/// <param name="NamePattern">Matched against WSC display names and installed-app display names.</param>
/// <param name="ServicePattern">Matched against service key names (null = no service evidence).</param>
public sealed record AvVendor(string Id, string Name, Regex NamePattern, Regex? ServicePattern, string? AccountUrl, string? Note = null);

/// <summary>
/// Known consumer antivirus vendors. Kept as a C# table (not an embedded file) so it ships inside the assembly.
/// NOTE: every AccountUrl below still NEEDS VERIFICATION (open each one in a browser before release); the
/// service names marked "verify in VM" come from vendor docs/community lists and have not been seen on a real install.
/// </summary>
public static class AvVendors
{
    const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    static Regex R(string p) => new(p, Opt, TimeSpan.FromSeconds(1));

    public const string DefenderId = "defender";

    public static readonly IReadOnlyList<AvVendor> All =
    [
        new(DefenderId, "Microsoft Defender", R(@"^(Windows|Microsoft) Defender"), null, null,
            "Built into Windows; status comes from Windows Security Center and Defender itself."),
        new("norton", "Norton", R(@"\bNorton\b"), R(@"^(NortonSvc|N360|NortonSecurity)$") /* verify in VM */, "https://my.norton.com"),
        new("mcafee", "McAfee", R(@"\bMcAfee\b"), R(@"^(mfemms|mfevtp|mfefire|McAPExe|ModuleCoreService)$"), "https://home.mcafee.com"),
        new("bitdefender", "Bitdefender", R(@"\bBitdefender\b"), R(@"^(VSSERV|bdredline)$"), "https://central.bitdefender.com"),
        new("kaspersky", "Kaspersky", R(@"\bKaspersky\b"), R(@"^AVP\d+(\.\d+)*$"), "https://my.kaspersky.com",
            "Kaspersky sales in the US ended in 2024."),
        new("ultraav", "UltraAV", R(@"\bUltraAV\b"), null /* service name: find in VM */, null /* account URL: verify */),
        new("eset", "ESET", R(@"\bESET\b"), R(@"^ekrn$"), "https://home.eset.com"),
        new("avast", "Avast", R(@"\bAvast\b"), R(@"^(avast! Antivirus|AvastWscReporter)$"), "https://id.avast.com"),
        new("avg", "AVG", R(@"\bAVG\b"), R(@"^(AVG Antivirus|AVGWscReporter)$"), "https://id.avg.com"),
        new("malwarebytes", "Malwarebytes", R(@"\bMalwarebytes\b"), R(@"^MBAMService$"), "https://my.malwarebytes.com",
            "Malwarebytes Free does not register with Windows Security Center."),
        new("webroot", "Webroot", R(@"\bWebroot\b"), R(@"^(WRSVC|WRCoreService)$"), "https://my.webrootanywhere.com"),
        new("trendmicro", "Trend Micro", R(@"\bTrend Micro\b"), R(@"^Amsp$"), "https://account.trendmicro.com"),
        new("sophoshome", "Sophos Home", R(@"\bSophos Home\b"), R(@"^(Sophos MCS Agent|Sophos Health Service|hmpalertsvc)$") /* verify in VM */, "https://home.sophos.com"),
    ];

    public static AvVendor? ByName(string? displayName) =>
        string.IsNullOrWhiteSpace(displayName) ? null : All.FirstOrDefault(v => v.NamePattern.IsMatch(displayName));

    public static AvVendor? ByService(string serviceName) =>
        All.FirstOrDefault(v => v.ServicePattern?.IsMatch(serviceName) == true);
}
