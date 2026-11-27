namespace PCPorter.Collectors.Signing;

/// <summary>
/// Who a signer name (the leaf certificate's display name) really is. "Contains Microsoft" is not enough: Microsoft
/// also signs OTHER companies' drivers ("Microsoft Windows Hardware Compatibility Publisher", the WHQL program, which is
/// how signed rootkits like Netfilter got through) and third-party components. Pure, unit-tested.
/// </summary>
public static class SignerNames
{
    static readonly HashSet<string> Microsoft = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft Windows Kits Publisher",
    };

    /// <summary>Signed by Microsoft for Microsoft's own code.</summary>
    public static bool IsMicrosoft(string? signer) => signer is not null && Microsoft.Contains(signer.Trim());

    /// <summary>Another company's driver, signed by Microsoft's hardware program (WHQL / attestation).</summary>
    public static bool IsWhql(string? signer) =>
        signer is not null && signer.Trim().Equals("Microsoft Windows Hardware Compatibility Publisher", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Publishers of well-known unwanted programs (browser hijackers, fake optimizers, adware). They sign their
    /// programs, so the "unsigned" rules never catch them. Matched as a substring of the signer name.
    /// </summary>
    static readonly string[] Unwanted =
    [
        "OneLaunch", "Wavesor", "Mindspark Interactive", "Spigot", "Crossrider", "Segurazo", "Restoro", "Reimage",
        "PC Accelerate", "ByteFence",
    ];

    /// <summary>The watchlist entry the signer matches, or null.</summary>
    public static string? UnwantedPublisher(string? signer) =>
        signer is null ? null : Unwanted.FirstOrDefault(u => signer.Contains(u, StringComparison.OrdinalIgnoreCase));
}
