using PCPorter.Core;
using PCPorter.Core.IO;

namespace PCPorter.Collectors.Sources;

/// <summary>
/// Another PC's Windows installation on an attached drive (dead-PC mode). Hives are parsed in memory, once each.
/// Nothing is written to the drive.
/// </summary>
public sealed class OfflineSource : ISystemSource
{
    readonly Dictionary<string, ParsedHive> _hives = new(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _notes = [];
    readonly Lazy<IReadOnlyList<UserProfile>> _users;

    public bool IsLive => false;
    public string ReadRoot { get; }
    public string OriginalSystemDrive { get; }
    public IReadOnlyList<string> Notes => _notes;
    public IReadOnlyList<UserProfile> Users => _users.Value;

    /// <param name="readRoot">"D:\" or a device path like \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\</param>
    /// <param name="runningWindowsDrive">Test hook only. By default this PC's own Windows is detected and refused.</param>
    /// <exception cref="SourceRejectedException">The running Windows, no Windows installation, or it cannot be read.</exception>
    public OfflineSource(string readRoot, string? runningWindowsDrive = null)
    {
        ReadRoot = readRoot.EndsWith('\\') ? readRoot : readRoot + "\\";

        // Refuse the running Windows however it is reached (C:\, \\?\C:\, \\.\C:\, volume GUID, subst, mounted folder,
        // shadow copy): compare the real identity (volume serial + file index) of the System32 folders, which every
        // account can query (the hive files themselves are admin-only).
        var running = runningWindowsDrive is null
            ? Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            : Path.Combine(runningWindowsDrive, "Windows");
        var runningId = FileIdentity.Identity(Path.Combine(running, "System32"));
        if (runningId is null && runningWindowsDrive is null)
            throw new SourceRejectedException("PCPorter could not tell which Windows is running, so it will not scan another drive.");
        if (runningId is not null && FileIdentity.Identity(Path.Combine(ReadRoot, "Windows", "System32")) == runningId)
            throw new SourceRejectedException("That is the Windows you are running now. Use a normal scan for this PC.");

        var hive = Path.Combine(ReadRoot, "Windows", "System32", "config", "SOFTWARE");
        if (!File.Exists(hive))
            throw new SourceRejectedException($"No Windows installation was found on {ReadRoot} (or it can only be read with administrator rights).");

        var cv = OpenHive(Hive.Software)?.Open(@"Microsoft\Windows NT\CurrentVersion");
        var sysRoot = cv?.GetString("SystemRoot");
        if (sysRoot is { Length: >= 2 } && sysRoot[1] == ':') OriginalSystemDrive = sysRoot[..2];
        else { OriginalSystemDrive = "C:"; _notes.Add("The old PC's Windows folder is not recorded; assumed it was on C:."); }

        if (!ReadRoot.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase) && FileIdentity.IsReadOnlyVolume(ReadRoot) == false)
            _notes.Add("This drive is not set to read-only. PCPorter does not write to it, but Windows itself may. See the read-only guide before connecting an old drive.");
        _users = new(() => SourcePaths.Profiles(OpenHive(Hive.Software), OriginalSystemDrive, MapPath));
    }

    public string? MapPath(string pathFromScannedPc) => SourcePaths.Map(pathFromScannedPc, OriginalSystemDrive, ReadRoot);

    public string? CurrentControlSet() => SourcePaths.ControlSetName(OpenHive(Hive.System));

    public IRegKey? OpenHive(Hive hive, UserProfile? user = null)
    {
        string? file = hive switch
        {
            Hive.Software => Path.Combine(ReadRoot, "Windows", "System32", "config", "SOFTWARE"),
            Hive.System => Path.Combine(ReadRoot, "Windows", "System32", "config", "SYSTEM"),
            Hive.NtUser => user?.ProfilePath is { } p ? Path.Combine(p, "NTUSER.DAT") : null,
            Hive.UsrClass => user?.ProfilePath is { } p ? Path.Combine(p, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat") : null,
            _ => null,
        };
        if (file is null) return null;
        if (!_hives.TryGetValue(file, out var parsed))
        {
            parsed = File.Exists(file) ? HiveParser.Parse(file) : new ParsedHive(null, false, false, $"{Path.GetFileName(file)} not found{(user is null ? "" : " for " + user.UserName)}.");
            _hives[file] = parsed;
            if (parsed.Problem is not null) _notes.Add(parsed.Problem);
        }
        return parsed.Root;
    }

    public void Dispose() => _hives.Clear();
}
