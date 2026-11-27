namespace PCPorter.Collectors.Offline;

/// <summary>
/// Text for the read-only attach wizard: diskpart scripts and the plain-words steps around them. This class only
/// produces text; it never runs diskpart. Only disk-level, in-memory attributes are used - never
/// "attributes volume" or "gpt attributes", which write a persistent flag onto the old disk.
/// </summary>
public static class ReadOnlyAttachGuide
{
    public static readonly IReadOnlyList<string> SanPolicies = ["OnlineAll", "OfflineAll", "OfflineShared", "OfflineInternal"];

    /// <summary>Shows the current SAN policy (run before changing it, so it can be restored).</summary>
    public static string QuerySanPolicyScript() => "san\r\n";

    /// <summary>Before plugging in the old drive: new disks stay offline, so Windows does not mount (and write to) them.</summary>
    public static string BeforeAttachScript() => "san policy=OfflineAll\r\n";

    /// <summary>After plugging in: make the old disk read-only, then bring it online.</summary>
    public static string AfterAttachScript(int diskNumber)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(diskNumber);
        return $"select disk {diskNumber}\r\nattributes disk set readonly\r\nonline disk\r\n";
    }

    /// <summary>Puts the SAN policy back to what it was before the wizard.</summary>
    public static string RestorePolicyScript(string previousPolicy)
    {
        var policy = SanPolicies.FirstOrDefault(p => string.Equals(p, previousPolicy?.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException($"Unknown SAN policy '{previousPolicy}'.", nameof(previousPolicy));
        return $"san policy={policy}\r\n";
    }

    /// <summary>Reads the policy from diskpart's "san" output ("SAN Policy  : Offline Shared"); null if not found.</summary>
    public static string? ParseSanPolicy(string diskpartOutput)
    {
        foreach (var line in diskpartOutput.Split('\n'))
        {
            int colon = line.IndexOf(':');
            if (colon < 0 || !line[..colon].Trim().Equals("SAN Policy", StringComparison.OrdinalIgnoreCase)) continue;
            var value = line[(colon + 1)..].Replace(" ", "", StringComparison.Ordinal).Trim();
            return SanPolicies.FirstOrDefault(p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase));
        }
        return null;
    }

    /// <summary>The wizard's steps in plain words.</summary>
    public static IReadOnlyList<string> Steps(int? diskNumber = null) =>
    [
        "Do not plug in the old drive yet.",
        "PCPorter asks Windows to keep newly attached disks offline (SAN policy OfflineAll), so nothing is written to the old drive when it is plugged in.",
        "Plug in the old drive.",
        diskNumber is { } n
            ? $"PCPorter marks disk {n} read-only for this session, then brings it online."
            : "Pick the old drive in the list; PCPorter marks it read-only for this session, then brings it online.",
        "After the scan, PCPorter puts the SAN policy back to what it was.",
    ];
}
