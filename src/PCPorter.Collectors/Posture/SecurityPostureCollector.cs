namespace PCPorter.Collectors.Posture;

/// <summary>
/// Read-only security settings review: support status, backups, updates, antivirus, firewall, risky settings.
/// Works on the running PC and (mostly) on another PC's drive; checks that need the running PC say so.
/// A check that cannot be determined is reported as Unknown - never guessed. Bad data never throws out of Run.
/// </summary>
public sealed class SecurityPostureCollector(PostureOptions? options = null) : ICollector
{
    readonly PostureOptions _options = options ?? new PostureOptions();

    public const string Kind = "posture";
    public string Name => "Security settings";

    public CollectorOutput Run(CollectorContext context, CancellationToken ct)
    {
        var items = new List<PostureCheck>();
        var notes = new List<string>();
        bool partial = false;

        PostureScan scan;
        try { scan = new PostureScan(context, _options); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            context.Warnings.Add($"Security settings: the registry could not be opened ({e.GetType().Name}).");
            return new CollectorOutput(Kind, [], notes, CollectorStatus.Failed);
        }

        using (scan)
        {
            if (scan.Software is null) notes.Add("The SOFTWARE registry hive could not be read; several security checks are Unknown.");
            if (scan.System is null) notes.Add("The SYSTEM registry hive could not be read; several security checks are Unknown.");
            if (!scan.IsLive) notes.Add("Some checks (accounts, open network ports, antivirus status) can only be done on the running PC.");

            var steps = new (string Id, string Title, string What, Func<PostureScan, IEnumerable<PostureCheck>> Run)[]
            {
                (PostureIds.WindowsSupport, "Windows support", "Checking Windows support dates", s => [SystemChecks.WindowsSupport(s)]),
                (PostureIds.Backup, "Backups", "Checking backups", s => [UserChecks.Backup(s)]),
                (PostureIds.WindowsUpdate, "Windows updates", "Checking Windows updates", s => [SystemChecks.WindowsUpdate(s)]),
                (PostureIds.Defender, "Microsoft Defender", "Checking Microsoft Defender", s => [AccountChecks.Defender(s)]),
                (PostureIds.Firewall, "Firewall", "Checking the firewall", s => [SystemChecks.Firewall(s)]),
                (PostureIds.RootCertificates, "Trusted certificates", "Checking trusted certificates", s => [UserChecks.RootCertificates(s)]),
                (PostureIds.AutoLogon, "Automatic sign-in", "Checking automatic sign-in", s => [AccountChecks.AutoLogon(s)]),
                (PostureIds.LocalAccounts, "Local accounts", "Checking local accounts", s => [AccountChecks.LocalAccounts(s)]),
                (PostureIds.BrowserExtensions, "Forced browser extensions", "Checking browser extensions", NetworkChecks.BrowserExtensions),
                (PostureIds.Proxy, "Web proxy", "Checking proxy settings", s => [NetworkChecks.Proxy(s)]),
                (PostureIds.Dns, "DNS servers", "Checking DNS settings", s => [NetworkChecks.Dns(s)]),
                (PostureIds.HostsFile, "Hosts file", "Checking the hosts file", s => [NetworkChecks.HostsFile(s)]),
                (PostureIds.Smb1, "Old file sharing (SMB1)", "Checking file sharing", s => [SystemChecks.Smb1(s)]),
                (PostureIds.RemoteDesktop, "Remote Desktop", "Checking Remote Desktop", s => [SystemChecks.RemoteDesktop(s)]),
                (PostureIds.Uac, "User Account Control", "Checking User Account Control", s => [SystemChecks.Uac(s)]),
                (PostureIds.ListeningPorts, "Open network ports", "Checking open network ports", s => [NetworkChecks.ListeningPorts(s)]),
                (PostureIds.MemoryIntegrity, "Memory integrity", "Checking memory integrity", s => [SystemChecks.MemoryIntegrity(s)]),
                (PostureIds.LsaProtection, "Sign-in secrets protection", "Checking LSA protection", s => [SystemChecks.LsaProtection(s)]),
                (PostureIds.SmartAppControl, "Smart App Control", "Checking Smart App Control", s => [SystemChecks.SmartAppControl(s)]),
                (PostureIds.PendingReboot, "Restart pending", "Checking for a pending restart", s => [SystemChecks.PendingReboot(s)]),
                (PostureIds.DiskSpace, "Free disk space", "Checking free disk space", s => [SystemChecks.DiskSpace(s)]),
            };

            foreach (var (id, title, what, run) in steps)
            {
                if (ct.IsCancellationRequested) break;
                context.Progress?.Report(what);
                try { items.AddRange(run(scan)); }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    partial = true;
                    context.Warnings.Add($"Security check '{id}' could not be completed ({e.GetType().Name}).");
                    items.Add(new PostureCheck(id, title, PostureStatus.Unknown, PostureSeverity.Info,
                        "PCPorter could not finish this check.", "Nothing to do now; the rest of the report is still valid.",
                        $"{e.GetType().Name} while checking."));
                }
            }
        }

        var status = ct.IsCancellationRequested ? CollectorStatus.Cancelled : partial ? CollectorStatus.Partial : CollectorStatus.Ok;
        return new CollectorOutput(Kind, items.Cast<IScanItem>().ToList(), notes, status);
    }
}
