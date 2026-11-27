using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Health;

/// <summary>Whether the scanned PC is managed by an organisation (domain, or Entra ID / Intune).</summary>
public static class JoinState
{
    /// <summary>Domain join from the hives: a primary DNS suffix set by the join (Tcpip\Parameters\Domain). Null if SYSTEM is unreadable.</summary>
    public static bool? DomainJoinedFromHive(IRegKey? system, string? ccs)
    {
        if (system is null || ccs is null) return null;
        var tcpip = system.Open($@"{ccs}\Services\Tcpip\Parameters");
        if (tcpip is null) return null;
        return !string.IsNullOrWhiteSpace(tcpip.GetString("Domain"));
    }

    /// <summary>Entra/Intune: an MDM enrollment with a UPN, or a CloudDomainJoin\JoinInfo entry.</summary>
    public static bool? EntraJoinedFromHive(IRegKey? software, IRegKey? system, string? ccs)
    {
        if (software is null && system is null) return null;
        var enrolled = software?.Open(@"Microsoft\Enrollments")?.SubKeys.Any(k => !string.IsNullOrWhiteSpace(k.GetString("UPN"))) == true;
        var joinInfo = ccs is not null && system?.Open($@"{ccs}\Control\CloudDomainJoin\JoinInfo")?.SubKeys.Any() == true;
        return enrolled || joinInfo;
    }

    /// <summary>Live: Win32_ComputerSystem.PartOfDomain (null if WMI did not answer).</summary>
    public static bool? DomainJoinedFromWmi(IWmiClient wmi)
    {
        var r = wmi.Query(@"root\cimv2", "SELECT PartOfDomain FROM Win32_ComputerSystem");
        return r.Outcome == WmiOutcome.Ok && r.Rows.Count > 0 ? WmiValue.Bool(r.Rows[0], "PartOfDomain") : null;
    }
}
