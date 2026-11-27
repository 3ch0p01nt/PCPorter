namespace PCPorter.Collectors.Posture;

/// <summary>Outcome of one security setting check. Unknown means "could not be determined" - we never guess.</summary>
public enum PostureStatus { Good, Attention, Risk, Unknown, NotApplicable }

public enum PostureSeverity { Info, Low, Medium, High, Critical }

/// <summary>
/// One read-only security setting check, written for a non-technical owner.
/// </summary>
/// <param name="Id">Stable check id (also the ItemKey), e.g. "firewall".</param>
/// <param name="Title">Plain-English name of the check.</param>
/// <param name="Finding">Plain English: what we saw.</param>
/// <param name="Advice">Plain English: what to do (calm; never scary).</param>
/// <param name="Evidence">Technical detail for the appendix (registry values, counts...).</param>
/// <param name="LiveOnly">True when the check can only be done on the running PC (not from a drive).</param>
public sealed record PostureCheck(string Id, string Title, PostureStatus Status, PostureSeverity Severity,
    string Finding, string Advice, string Evidence, bool LiveOnly = false) : IScanItem
{
    public string ItemKey => Id;
}

/// <summary>Check ids, so the UI, the report and tests share one spelling.</summary>
public static class PostureIds
{
    public const string WindowsSupport = "windows-support";
    public const string Backup = "backup";
    public const string WindowsUpdate = "windows-update";
    public const string Defender = "defender";
    public const string Firewall = "firewall";
    public const string RootCertificates = "root-certificates";
    public const string AutoLogon = "auto-logon";
    public const string LocalAccounts = "local-accounts";
    public const string BrowserExtensions = "browser-extensions";
    public const string BrowserExtensionPrefix = "browser-extension:";
    public const string Proxy = "proxy";
    public const string Dns = "dns";
    public const string HostsFile = "hosts-file";
    public const string Smb1 = "smb1";
    public const string RemoteDesktop = "remote-desktop";
    public const string Uac = "uac";
    public const string ListeningPorts = "listening-ports";
    public const string MemoryIntegrity = "memory-integrity";
    public const string LsaProtection = "lsa-protection";
    public const string SmartAppControl = "smart-app-control";
    public const string PendingReboot = "pending-reboot";
    public const string DiskSpace = "disk-space";
}
