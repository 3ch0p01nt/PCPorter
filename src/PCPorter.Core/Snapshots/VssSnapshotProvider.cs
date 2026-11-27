using System.Management;

namespace PCPorter.Core.Snapshots;

/// <summary>
/// Creates Volume Shadow Copy snapshots through Windows' own WMI provider (Win32_ShadowCopy), so locked files
/// (browser databases, PSTs) can be read consistently. No third-party or native libraries. Requires admin.
/// </summary>
public sealed class VssSnapshotProvider(string? journalPath = null) : ISnapshotProvider
{
    /// <summary>IDs of shadow copies PCPorter created and has not yet deleted (so a crash never leaves them behind).</summary>
    /// Kept in an admin-only folder: a normal user must not be able to add IDs that an elevated run would then delete.
    readonly string _journal = journalPath ?? Path.Combine(PCPorter.Core.Security.AppFolders.For("state"), "shadow-copies.txt");

    /// <summary>Deletes shadow copies left behind by an earlier crashed run. Only ever touches IDs PCPorter recorded.</summary>
    public int CleanUpStale()
    {
        if (!File.Exists(_journal)) return 0;
        int removed = 0;
        foreach (var id in File.ReadAllLines(_journal).Where(l => Guid.TryParse(l, out _)).Distinct())
        {
            removed += Delete(id);
            Forget(id);
        }
        return removed;
    }

    public ISnapshot Create(string volumeRoot)
    {
        CleanUpStale();
        if (!volumeRoot.EndsWith('\\')) volumeRoot += "\\";
        using var shadowClass = new ManagementClass(@"root\cimv2", "Win32_ShadowCopy", null);
        using var input = shadowClass.GetMethodParameters("Create");
        input["Volume"] = volumeRoot;
        input["Context"] = "ClientAccessible";
        using var output = shadowClass.InvokeMethod("Create", input, null);
        var code = Convert.ToUInt32(output["ReturnValue"]);
        if (code != 0) throw new InvalidOperationException($"Windows could not create a shadow copy of {volumeRoot} (code {code}: {Describe(code)}).");

        if (!Guid.TryParse(output["ShadowID"] as string, out var gid))
            throw new InvalidOperationException("Windows created a shadow copy but returned an unreadable ID.");
        var id = gid.ToString("B");
        Remember(id);
        string? device;
        using (var searcher = new ManagementObjectSearcher(@"root\cimv2", $"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID='{gid:B}'"))
            device = searcher.Get().Cast<ManagementObject>().Select(o => (string)o["DeviceObject"]).FirstOrDefault();
        if (device is null)
        {
            Delete(id);
            Forget(id);
            throw new InvalidOperationException($"The shadow copy {id} was created but could not be found; it has been removed.");
        }
        return new Snapshot(id, volumeRoot, device, () => { Delete(id); Forget(id); });
    }

    static int Delete(string id)
    {
        if (!Guid.TryParse(id, out var g)) return 0;       // only well-formed IDs ever reach the WQL query
        int n = 0;
        using var searcher = new ManagementObjectSearcher(@"root\cimv2", $"SELECT * FROM Win32_ShadowCopy WHERE ID='{g:B}'");
        foreach (ManagementObject o in searcher.Get()) using (o) { o.Delete(); n++; }
        return n;
    }

    void Remember(string id)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_journal)!);
        File.AppendAllLines(_journal, [id]);
    }

    void Forget(string id)
    {
        if (!File.Exists(_journal)) return;
        var rest = File.ReadAllLines(_journal).Where(l => !l.Equals(id, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (rest.Length == 0) File.Delete(_journal); else File.WriteAllLines(_journal, rest);
    }

    /// <summary>Maps a live path on <paramref name="volumeRoot"/> into the snapshot device. Paths on other volumes throw.</summary>
    public static string MapPath(string device, string volumeRoot, string livePath)
    {
        var root = volumeRoot.TrimEnd('\\');   // Path.TrimEndingDirectorySeparator keeps the slash on "C:\"
        if (livePath.Equals(root, StringComparison.OrdinalIgnoreCase) || livePath.Equals(root + "\\", StringComparison.OrdinalIgnoreCase))
            return device + "\\";
        if (!livePath.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"{livePath} is not on the snapshot volume {volumeRoot}.", nameof(livePath));
        return device + "\\" + livePath[(root.Length + 1)..];
    }

    static string Describe(uint code) => code switch
    {
        1 => "access denied - run as administrator",
        2 => "invalid argument",
        3 => "volume not found",
        4 => "volume not supported",
        5 => "unsupported shadow copy context",
        6 => "not enough storage",
        7 => "volume is in use",
        8 => "maximum number of shadow copies reached",
        9 => "another shadow copy operation is in progress",
        10 => "shadow copy provider error",
        11 => "shadow copy provider not registered",
        12 => "shadow copy provider veto",
        13 => "shadow copy provider not found",
        _ => "unknown error",
    };

    sealed class Snapshot(string id, string volumeRoot, string device, Action delete) : ISnapshot
    {
        bool _disposed;
        public string Id => id;
        public string DeviceRoot => device;
        public string Map(string livePath) => MapPath(device, volumeRoot, livePath);

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            delete();
        }
    }

    /// <summary>Existing shadow copies (restore points) of a volume, oldest first. Read-only: never creates any.</summary>
    public static IReadOnlyList<(string Id, string DeviceObject, DateTimeOffset Created)> ListExisting(string volumeRoot)
    {
        var list = new List<(string, string, DateTimeOffset)>();
        if (!IsDriveLetter(volumeRoot.TrimEnd('\\'))) return list;
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT ID, DeviceObject, InstallDate, VolumeName FROM Win32_ShadowCopy");
            var volumeName = VolumeName(volumeRoot);
            foreach (ManagementObject o in searcher.Get())
                using (o)
                {
                    if (volumeName is not null && !string.Equals((string?)o["VolumeName"], volumeName, StringComparison.OrdinalIgnoreCase)) continue;
                    var created = o["InstallDate"] is string s ? ManagementDateTimeConverter.ToDateTime(s).ToUniversalTime() : DateTime.MinValue;
                    list.Add(((string)o["ID"], (string)o["DeviceObject"], new DateTimeOffset(created, TimeSpan.Zero)));
                }
        }
        catch (ManagementException) { }
        catch (UnauthorizedAccessException) { }
        return list.OrderBy(x => x.Item3).ToList();
    }

    public static bool IsDriveLetter(string s) => s.Length == 2 && char.IsAsciiLetter(s[0]) && s[1] == ':';

    static string? VolumeName(string volumeRoot)
    {
        var letter = volumeRoot.TrimEnd('\\');
        if (!IsDriveLetter(letter)) throw new ArgumentException($"{volumeRoot} is not a drive like C:\\.", nameof(volumeRoot));   // only "X:" ever reaches WQL
        try
        {
            using var s = new ManagementObjectSearcher(@"root\cimv2", $"SELECT DeviceID FROM Win32_Volume WHERE DriveLetter='{letter}'");
            return s.Get().Cast<ManagementObject>().Select(o => (string)o["DeviceID"]).FirstOrDefault();
        }
        catch (ManagementException) { return null; }
    }
}
