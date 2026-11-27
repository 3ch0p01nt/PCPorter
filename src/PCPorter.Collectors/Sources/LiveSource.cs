using Microsoft.Win32;

namespace PCPorter.Collectors.Sources;

/// <summary>
/// This running PC. Registry is read live and read-only (no shadow copies, no hive copies - that pattern looks like
/// credential theft to security software). Signed-out users' NTUSER.DAT files are parsed in memory.
/// </summary>
public sealed class LiveSource : ISystemSource
{
    readonly List<string> _notes = [];
    readonly Dictionary<string, ParsedHive> _offlineUserHives = new(StringComparer.OrdinalIgnoreCase);
    readonly Lazy<IReadOnlyList<UserProfile>> _users;

    public bool IsLive => true;
    public string ReadRoot { get; }
    public string OriginalSystemDrive { get; }
    public IReadOnlyList<string> Notes => _notes;
    public IReadOnlyList<UserProfile> Users => _users.Value;

    public LiveSource()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        OriginalSystemDrive = windows[..2];
        ReadRoot = OriginalSystemDrive + "\\";
        _users = new(() => SourcePaths.Profiles(OpenHive(Hive.Software), OriginalSystemDrive, MapPath));
    }

    public string? MapPath(string pathFromScannedPc) => SourcePaths.Map(pathFromScannedPc, OriginalSystemDrive, ReadRoot);

    public string? CurrentControlSet() => SourcePaths.ControlSetName(OpenHive(Hive.System));

    public IRegKey? OpenHive(Hive hive, UserProfile? user = null)
    {
        switch (hive)
        {
            case Hive.Software: return LiveRegKey.Open(RegistryHive.LocalMachine, "SOFTWARE");
            case Hive.System: return LiveRegKey.Open(RegistryHive.LocalMachine, "SYSTEM");
            case Hive.NtUser or Hive.UsrClass when user is not null:
                var live = LiveRegKey.Open(RegistryHive.Users, hive == Hive.NtUser ? user.Sid : user.Sid + "_Classes");
                if (live is not null) return live;                     // user is signed in: hive is loaded
                if (user.ProfilePath is null) return null;
                var file = hive == Hive.NtUser
                    ? Path.Combine(user.ProfilePath, "NTUSER.DAT")
                    : Path.Combine(user.ProfilePath, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat");
                if (!_offlineUserHives.TryGetValue(file, out var parsed))
                {
                    parsed = File.Exists(file) ? HiveParser.Parse(file) : new ParsedHive(null, false, false, $"{Path.GetFileName(file)} not found for {user.UserName}.");
                    _offlineUserHives[file] = parsed;
                    if (parsed.Problem is not null) _notes.Add(parsed.Problem);
                }
                return parsed.Root;
            default: return null;
        }
    }

    public void Dispose() => _offlineUserHives.Clear();
}
