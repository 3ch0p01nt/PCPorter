using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using PCPorter.Core.IO;
using PCPorter.Core.Security;

namespace PCPorter.Core.Snapshots;

/// <summary>
/// Creates Volume Shadow Copy snapshots through Windows' own WMI provider (Win32_ShadowCopy), so locked files
/// (browser databases, PSTs) can be read consistently. No third-party or native libraries. Requires admin.
/// </summary>
/// <remarks>
/// Every snapshot is recorded in a journal so a crash never leaves one behind: a "pending" line is written BEFORE
/// Windows is asked, and replaced by a "created" line (ID, volume, creation time, owning process) right after. A later
/// run deletes only entries whose owning process has ended, and only a shadow copy that still matches what was
/// recorded and was made in PCPorter's own context (client-accessible, no writers), never a restore point.
/// </remarks>
public sealed class VssSnapshotProvider : ISnapshotProvider
{
    readonly Journal _journal;
    readonly IShadowCopies _shadows;
    readonly Func<int, long, bool> _isAlive;
    readonly (int Pid, long Started) _self;
    readonly Func<DateTime> _utcNow;

    /// <summary>How far from a pending line's time a shadow copy may have been made and still be the one it describes.</summary>
    internal static readonly TimeSpan PendingWindow = TimeSpan.FromMinutes(2);

    /// <exception cref="UnsafeAppFolderException">Elevated, and the journal's admin-only folder could not be made safe.</exception>
    public VssSnapshotProvider(string? journalPath = null)
        : this(journalPath ?? Path.Combine(AppFolders.For("state"), "shadow-copies.txt"), new WmiShadowCopies(), AppFolders.IsElevated,
               IsProcessAlive, CurrentProcess(), () => DateTime.UtcNow)
    {
    }

    internal VssSnapshotProvider(string journalPath, IShadowCopies shadows, bool requireAdminOwnedJournal,
        Func<int, long, bool> isAlive, (int Pid, long Started) self, Func<DateTime> utcNow)
    {
        _journal = new Journal(journalPath, requireAdminOwnedJournal);
        _shadows = shadows;
        _isAlive = isAlive;
        _self = self;
        _utcNow = utcNow;
    }

    /// <summary>
    /// Deletes shadow copies left behind by an earlier run that has ended (crashed). Only ever touches copies PCPorter
    /// recorded, whose owning process is gone, and that still match the record. Returns how many were deleted.
    /// </summary>
    public int CleanUpStale() => _journal.Update(lines =>
    {
        var entries = lines.Select(Entry.Parse).ToList();
        var keep = new List<Entry>();
        int removed = 0;
        IReadOnlyList<ShadowInfo>? all = null;
        IReadOnlyList<ShadowInfo> All() => all ??= _shadows.List();

        foreach (var e in entries)
        {
            if (e is null) continue;                                         // malformed or old-format line: dropped, nothing deleted
            if (_isAlive(e.Pid, e.Started)) { keep.Add(e); continue; }        // another live run (GUI or CLI) owns it
            if (e.Kind == "created")
            {
                var s = All().FirstOrDefault(x => x.Id.Equals(e.Key, StringComparison.OrdinalIgnoreCase));
                if (s is not null && IsOurs(s) && s.VolumeName.Equals(e.Volume, StringComparison.OrdinalIgnoreCase) && s.InstallDate == e.Detail)
                {
                    _shadows.Delete(s.Id);
                    removed++;
                }
            }
            else
            {
                // Crashed between asking Windows and recording the ID: the copy made on that volume in the window, if
                // exactly one, not recorded by anyone, and no live run could have made it at the same time.
                var volumeName = _shadows.VolumeName(e.Volume);
                if (volumeName is null || !DateTime.TryParse(e.Detail, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at)) continue;
                bool liveRunNearby = entries.Any(o => o is { Kind: "pending" } && !ReferenceEquals(o, e) && _isAlive(o.Pid, o.Started)
                                                      && o.Volume.Equals(e.Volume, StringComparison.OrdinalIgnoreCase));
                if (liveRunNearby) { keep.Add(e); continue; }
                var recorded = entries.Where(o => o is { Kind: "created" }).Select(o => o!.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var candidates = All().Where(s => IsOurs(s) && s.VolumeName.Equals(volumeName, StringComparison.OrdinalIgnoreCase)
                                                  && !recorded.Contains(s.Id) && s.InstallUtc >= at.AddSeconds(-5) && s.InstallUtc <= at + PendingWindow).ToList();
                if (candidates.Count == 1)
                {
                    _shadows.Delete(candidates[0].Id);
                    removed++;
                }
            }
        }
        lines.Clear();
        lines.AddRange(keep.Select(k => k.ToString()));
        return removed;
    });

    public ISnapshot Create(string volumeRoot)
    {
        CleanUpStale();
        if (!volumeRoot.EndsWith('\\')) volumeRoot += "\\";
        var token = Guid.NewGuid().ToString("N");
        var started = _utcNow();
        var pending = new Entry("pending", token, _self.Pid, _self.Started, volumeRoot, started.ToString("O", CultureInfo.InvariantCulture));
        _journal.Update(l => { l.Add(pending.ToString()); return 0; });

        uint code;
        string? rawId;
        try { (code, rawId) = _shadows.Create(volumeRoot); }
        catch { Remove(token); throw; }
        if (code != 0)
        {
            Remove(token);
            throw new InvalidOperationException($"Windows could not create a shadow copy of {volumeRoot} (code {code}: {Describe(code)}).");
        }

        ShadowInfo? info;
        if (Guid.TryParse(rawId, out var gid))
        {
            info = _shadows.List().FirstOrDefault(s => Guid.TryParse(s.Id, out var g) && g == gid);
            if (info is null || string.IsNullOrEmpty(info.DeviceObject))
            {
                _shadows.Delete(gid.ToString("B"));
                Remove(token);
                throw new InvalidOperationException($"The shadow copy {gid:B} was created but could not be found; it has been removed.");
            }
        }
        else
        {
            // Unreadable ID: find it by volume and time. If that is not certain, the pending line stays, so a later run
            // (after this one has ended) removes it.
            var volumeName = _shadows.VolumeName(volumeRoot);
            var candidates = _shadows.List().Where(s => IsOurs(s) && s.VolumeName.Equals(volumeName ?? "", StringComparison.OrdinalIgnoreCase)
                                                        && s.InstallUtc >= started.AddSeconds(-5) && s.InstallUtc <= _utcNow().AddSeconds(5)
                                                        && !Recorded(s.Id)).ToList();
            if (candidates.Count != 1 || string.IsNullOrEmpty(candidates[0].DeviceObject))
                throw new InvalidOperationException("Windows created a shadow copy but returned an unreadable ID. It will be removed the next time PCPorter runs.");
            info = candidates[0];
        }

        var id = info.Id;
        var created = new Entry("created", id, _self.Pid, _self.Started, info.VolumeName, info.InstallDate);
        _journal.Update(l => { l.RemoveAll(x => Entry.Parse(x)?.Key == token); l.Add(created.ToString()); return 0; });
        return new Snapshot(id, volumeRoot, info.DeviceObject, () => { _shadows.Delete(id); Forget(id); });
    }

    /// <summary>PCPorter's own context (ClientAccessible: persistent, no writers). Restore points involve writers.</summary>
    static bool IsOurs(ShadowInfo s) => s.ClientAccessible && s.NoWriters;

    bool Recorded(string id) => _journal.Update(l => l.Select(Entry.Parse).Any(e => e?.Key.Equals(id, StringComparison.OrdinalIgnoreCase) == true));

    void Remove(string token) => _journal.Update(l => l.RemoveAll(x => Entry.Parse(x)?.Key == token));

    void Forget(string id) => _journal.Update(l => l.RemoveAll(x => Entry.Parse(x)?.Key.Equals(id, StringComparison.OrdinalIgnoreCase) == true));

    static (int, long) CurrentProcess()
    {
        using var p = Process.GetCurrentProcess();
        return (p.Id, p.StartTime.ToUniversalTime().Ticks);
    }

    /// <summary>True while the process that wrote an entry still runs (same id AND same start time, so a reused id does not count).</summary>
    static bool IsProcessAlive(int pid, long startedTicks)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return false;
            return Math.Abs(p.StartTime.ToUniversalTime().Ticks - startedTicks) < TimeSpan.TicksPerSecond;
        }
        catch (ArgumentException) { return false; }                     // no such process
        catch (InvalidOperationException) { return false; }              // exited meanwhile
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or NotSupportedException) { return true; }   // cannot tell: assume alive
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

    /// <summary>One journal line: kind, key (shadow ID or pending token), owner pid + start, volume, detail (install date or start time).</summary>
    sealed record Entry(string Kind, string Key, int Pid, long Started, string Volume, string Detail)
    {
        public override string ToString() => string.Join('\t', Kind, Key, Pid.ToString(CultureInfo.InvariantCulture),
            Started.ToString(CultureInfo.InvariantCulture), Volume, Detail);

        public static Entry? Parse(string line)
        {
            var f = line.Split('\t');
            if (f.Length != 6 || f[0] is not ("pending" or "created")) return null;
            if (!int.TryParse(f[2], NumberStyles.None, CultureInfo.InvariantCulture, out var pid)) return null;
            if (!long.TryParse(f[3], NumberStyles.None, CultureInfo.InvariantCulture, out var started)) return null;
            if (f[0] == "created" && !Guid.TryParse(f[1], out _)) return null;
            return new Entry(f[0], f[1], pid, started, f[4], f[5]);
        }
    }

    /// <summary>
    /// The journal file, read and rewritten under an exclusive lock (a GUI and a CLI run may share it). When elevated
    /// it must be a plain file (no link, one hard link) owned by and writable only by SYSTEM/Administrators; otherwise
    /// its contents are ignored and it is recreated with that ACL.
    /// </summary>
    sealed class Journal(string path, bool requireAdminOwned)
    {
        public T Update<T>(Func<List<string>, T> change)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            using var fs = Open();
            var lines = new List<string>();
            using (var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
                while (reader.ReadLine() is { } line) if (line.Length > 0) lines.Add(line);
            var result = change(lines);
            fs.SetLength(0);
            using (var writer = new StreamWriter(fs, new UTF8Encoding(false), leaveOpen: true))
                foreach (var l in lines) writer.WriteLine(l);
            return result;
        }

        FileStream Open()
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (FileIdentity.Entry(path) is { IsReparsePoint: true }) File.Delete(path);     // removes the link itself
                    if (!File.Exists(path)) return CreateNew();
                    var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    if (Trusted(fs)) return fs;
                    fs.Dispose();
                    File.Delete(path);                          // its contents cannot be trusted: start a new, locked journal
                    return CreateNew();
                }
                catch (IOException e) when (attempt < 600 && IsSharingViolation(e)) { Thread.Sleep(50); }
            }
        }

        bool Trusted(FileStream fs)
        {
            if (FileIdentity.LinkCount(fs.SafeFileHandle) is not 1u) return false;
            return !requireAdminOwned || AppFolders.IsAdminOnly(fs.GetAccessControl());
        }

        FileStream CreateNew()
        {
            if (!requireAdminOwned) return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.SetOwner(admins);
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.ReadPermissions,
                FileShare.None, 4096, FileOptions.None, sec);
        }

        // Sharing/lock violation (another run holds the lock), or the file appeared between the check and CreateNew.
        static bool IsSharingViolation(IOException e) => (e.HResult & 0xFFFF) is 32 or 33 or 80 or 183;
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

/// <summary>A shadow copy as Windows reports it. <see cref="InstallDate"/> is the raw WMI value, compared exactly.</summary>
internal sealed record ShadowInfo(string Id, string DeviceObject, string VolumeName, string InstallDate, DateTime InstallUtc, bool ClientAccessible, bool NoWriters);

/// <summary>Windows' shadow copies (Win32_ShadowCopy); a fake in tests.</summary>
internal interface IShadowCopies
{
    /// <summary>Asks Windows for a ClientAccessible shadow copy; returns the WMI return code and the raw ShadowID.</summary>
    (uint Code, string? Id) Create(string volumeRoot);
    IReadOnlyList<ShadowInfo> List();
    void Delete(string id);
    /// <summary>\\?\Volume{guid}\ for a root like C:\, as Win32_ShadowCopy.VolumeName reports it.</summary>
    string? VolumeName(string volumeRoot);
}

internal sealed class WmiShadowCopies : IShadowCopies
{
    public (uint Code, string? Id) Create(string volumeRoot)
    {
        using var shadowClass = new ManagementClass(@"root\cimv2", "Win32_ShadowCopy", null);
        using var input = shadowClass.GetMethodParameters("Create");
        input["Volume"] = volumeRoot;
        input["Context"] = "ClientAccessible";
        using var output = shadowClass.InvokeMethod("Create", input, null);
        return (Convert.ToUInt32(output["ReturnValue"], CultureInfo.InvariantCulture), output["ShadowID"] as string);
    }

    public IReadOnlyList<ShadowInfo> List()
    {
        var list = new List<ShadowInfo>();
        using var searcher = new ManagementObjectSearcher(@"root\cimv2",
            "SELECT ID, DeviceObject, VolumeName, InstallDate, ClientAccessible, NoWriters FROM Win32_ShadowCopy");
        foreach (ManagementObject o in searcher.Get())
            using (o)
            {
                var install = o["InstallDate"] as string ?? "";
                var utc = install.Length > 0 ? ManagementDateTimeConverter.ToDateTime(install).ToUniversalTime() : DateTime.MinValue;
                list.Add(new ShadowInfo(o["ID"] as string ?? "", o["DeviceObject"] as string ?? "", o["VolumeName"] as string ?? "", install, utc,
                    o["ClientAccessible"] is true, o["NoWriters"] is true));
            }
        return list;
    }

    public void Delete(string id)
    {
        if (!Guid.TryParse(id, out var g)) return;          // only well-formed IDs ever reach the WQL query
        using var searcher = new ManagementObjectSearcher(@"root\cimv2", $"SELECT * FROM Win32_ShadowCopy WHERE ID='{g:B}'");
        foreach (ManagementObject o in searcher.Get()) using (o) o.Delete();
    }

    public string? VolumeName(string volumeRoot)
    {
        var sb = new StringBuilder(64);
        var root = volumeRoot.EndsWith('\\') ? volumeRoot : volumeRoot + "\\";
        return GetVolumeNameForVolumeMountPoint(root, sb, (uint)sb.Capacity) ? sb.ToString() : null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetVolumeNameForVolumeMountPointW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeNameForVolumeMountPoint(string mountPoint, StringBuilder volumeName, uint size);
}
