using System.Globalization;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using PCPorter.Collectors.Offline;
using PCPorter.Collectors.Sources;
using PCPorter.Core.IO;

namespace PCPorter.App.Views;

/// <summary>A drive in the "another PC's drive" picker. Locked (BitLocker) drives are listed but can't be picked until unlocked.</summary>
/// <param name="Warning">Shown under the picker while this drive is picked (for example: not shut down cleanly).</param>
public sealed record DriveChoice(string Root, string Label, bool Usable, string? Warning = null)
{
    public override string ToString() => Label;
}

/// <summary>Finds connected drives that hold another PC's Windows (shared by the Health and security and Web history pages).</summary>
public static class WindowsDrives
{
    public const string LockedSuffix = " (locked or not ready)";

    /// <summary>
    /// Every fixed or removable drive other than the running Windows that holds a Windows (<see cref="OfflineVolumeFinder"/>:
    /// OS name, BitLocker-locked drives, never following a link), each checked by <see cref="VolumeSafety"/>. Drives that
    /// are not ready (locked without administrator rights to ask BitLocker) are listed but can't be picked. Slow for a
    /// sleeping USB disk and asks WMI: call off the UI thread.
    /// </summary>
    public static List<DriveChoice> Find()
    {
        var running = SystemRoot;
        var ready = new List<string>();
        var notReady = new List<string>();
        var unreadable = new List<string>();
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
        foreach (var d in drives)
        {
            string root;
            try
            {
                if (d.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
                root = d.RootDirectory.FullName;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            if (string.Equals(root, running, StringComparison.OrdinalIgnoreCase)) continue;
            try { (d.IsReady ? ready : notReady).Add(root); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { unreadable.Add(root); }
        }
        var scan = new OfflineVolumeFinder(new WmiClient(), () => ready, runningWindowsDrive: running, readOs: SafeReadOs).Find();
        // Only the two checks the picker shows (the change-journal position is for a scan's before/after comparison).
        return Choices(scan, notReady, unreadable, root => new VolumeSafetyReport(VolumeSafety.IsHibernated(root), VolumeSafety.IsDirty(root), null));
    }

    /// <summary>
    /// The OS name from an untrusted drive's hive. The finder turns read errors into a note; anything else a damaged
    /// hive throws must not end the app (the picker runs from an async void handler): the drive is then just "Windows found".
    /// </summary>
    static (string? OsName, string? Build) SafeReadOs(string root)
    {
        try { return OfflineVolumeFinder.ReadOs(root); }
        catch (Exception e) when (e is not (IOException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException
                                           or OutOfMemoryException or StackOverflowException))
        { return (null, null); }
    }

    /// <summary>
    /// The picker's entries: drives with Windows (usable; OS name; <see cref="VolumeSafetyReport.Warning"/> when hibernated
    /// or dirty), then locked drives and drives that are not ready (listed, not usable), then drives that can't be read.
    /// </summary>
    public static List<DriveChoice> Choices(OfflineVolumeScan scan, IEnumerable<string> notReady, IEnumerable<string> unreadable,
        Func<string, VolumeSafetyReport> safety)
    {
        var list = new List<DriveChoice>();
        foreach (var v in scan.Volumes.Where(v => v.State == OfflineVolumeState.WindowsFound && v.Root is not null))
        {
            list.Add(new(v.Root!, $"{v.Root} {v.Description}", true, safety(v.Root!).Warning));
        }
        var listed = new HashSet<string>(list.Select(c => c.Root), StringComparer.OrdinalIgnoreCase);
        foreach (var v in scan.Volumes.Where(v => v.State == OfflineVolumeState.Locked))
        {
            if (v.Root is { } root) { if (listed.Add(root)) list.Add(new(root, root + LockedSuffix, false)); }
            else list.Add(new("", "A drive without a letter" + LockedSuffix, false));
        }
        foreach (var root in notReady)
            if (listed.Add(root)) list.Add(new(root, root + LockedSuffix, false));
        foreach (var root in unreadable)
            if (listed.Add(root)) list.Add(new(root, $"{root} (can't be read)", false));
        return list;
    }

    /// <summary>
    /// The line under the picker: what was found and what to do next. Without administrator rights Windows hides another
    /// drive's system folder, so "nothing found" would be wrong: say how to look instead. The picked drive's warning
    /// (not shut down cleanly) comes first.
    /// </summary>
    public static string Hint(IReadOnlyCollection<DriveChoice> found, bool elevated, DriveChoice? picked = null)
    {
        var hint = found.Count == 0
            ? elevated
                ? "No other Windows drive found. Connect the old PC's drive (for example with a USB adapter) and press Refresh."
                : "Start PCPorter as administrator to look inside other drives."
            : found.Any(c => !c.Usable)
                ? "A locked drive was found. Unlock it in File Explorer with its BitLocker recovery key (aka.ms/myrecoverykey), then press Refresh."
                : "";
        return picked?.Warning is { } warning ? (hint.Length > 0 ? warning + " " + hint : warning) : hint;
    }

    /// <summary>A local folder outside any synced location: shown at once, until the backup drive is found.</summary>
    public const string DefaultSaveFolder = @"C:\PCPorterCases";

    /// <summary>Shown while the save folder is on the drive Windows runs from.</summary>
    public const string SystemDriveWarning = "Results saved on this PC are lost when it is reset: save to your backup drive.";

    /// <summary>The root of the drive Windows runs from, for example C:\.</summary>
    public static string SystemRoot => Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\";

    /// <summary>
    /// The drives worth saving to, best first: never the drive Windows runs from (it is about to be reset) nor a drive
    /// that holds another Windows (the old PC's drive, the one being checked). USB disks first (backup hard drives and
    /// SSDs say "Fixed", like the PC's own disk, so the bus is what tells them apart), then other removable drives (SD
    /// cards), then the rest; the most free space first within each, so a backup disk comes before a small stick.
    /// </summary>
    public static List<SaveDrive> RankSaveDrives(IEnumerable<SaveDrive> drives, string systemRoot) =>
        drives.Where(d => !string.Equals(d.Root, systemRoot, StringComparison.OrdinalIgnoreCase) && !d.HoldsWindows)
              .OrderByDescending(d => d.Usb ? 2 : d.Removable ? 1 : 0).ThenByDescending(d => d.FreeBytes)
              .ToList();

    /// <summary>
    /// True when <paramref name="folder"/> is on <paramref name="systemRoot"/>, also through a subst letter
    /// (<paramref name="dosDevice"/> answers what a letter maps to; an unusable path is not on it).
    /// </summary>
    public static bool IsOnSystemDrive(string? folder, string systemRoot, Func<string, string?>? dosDevice = null)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Path.IsPathFullyQualified(folder.Trim())) return false;
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(folder.Trim()));
            for (int hop = 0; root is { Length: 3 } && hop < 8; hop++)
            {
                if (string.Equals(root, systemRoot, StringComparison.OrdinalIgnoreCase)) return true;
                var target = dosDevice?.Invoke(root[..2]);
                if (target is null || !target.StartsWith(@"\??\", StringComparison.Ordinal) || target.Length < 6) return false;
                root = Path.GetPathRoot(target[4..]);         // subst S: C:\Some\Folder -> C:\
            }
            return false;
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    static bool IsSubst(string root) => FileIdentity.DosDeviceTarget(root[..2])?.StartsWith(@"\??\", StringComparison.Ordinal) == true;

    /// <summary>
    /// Every ready fixed or removable drive, ranked by <see cref="RankSaveDrives"/>. Slow for a sleeping USB disk (IsReady
    /// waits for it) and asks WMI which disks are on USB: call off the UI thread.
    /// </summary>
    public static List<SaveDrive> FindSaveDrives()
    {
        var usb = UsbDriveLetters();
        var all = new List<SaveDrive>();
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
        foreach (var d in drives)
        {
            try
            {
                if (d.DriveType is not (DriveType.Fixed or DriveType.Removable) || !d.IsReady) continue;
                var root = d.RootDirectory.FullName;
                if (IsSubst(root)) continue;                  // a subst letter is a folder of another drive, not a drive
                all.Add(new SaveDrive(root, d.VolumeLabel, d.AvailableFreeSpace, usb.Contains(char.ToUpperInvariant(root[0])),
                    d.DriveType == DriveType.Removable, Directory.Exists(Path.Combine(root, "Windows", "System32"))));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return RankSaveDrives(all, SystemRoot);
    }

    /// <summary>Drive letters on USB disks (Storage WMI: MSFT_Disk.BusType 7 = USB, MSFT_Partition for the letters). Empty when WMI can't say.</summary>
    static HashSet<char> UsbDriveLetters()
    {
        var letters = new HashSet<char>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
            var options = new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(10) };
            var disks = new HashSet<uint>();
            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Number FROM MSFT_Disk WHERE BusType = 7"), options))
            using (var found = q.Get())
                foreach (var disk in found)
                    using (disk) disks.Add(Convert.ToUInt32(disk["Number"], CultureInfo.InvariantCulture));
            if (disks.Count == 0) return letters;
            using (var q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT DiskNumber, DriveLetter FROM MSFT_Partition"), options))
            using (var found = q.Get())
                foreach (var part in found)
                    using (part)
                    {
                        if (part["DriveLetter"] is not { } value || !disks.Contains(Convert.ToUInt32(part["DiskNumber"], CultureInfo.InvariantCulture))) continue;
                        var letter = char.ToUpperInvariant(Convert.ToChar(value, CultureInfo.InvariantCulture));
                        if (char.IsAsciiLetter(letter)) letters.Add(letter);
                    }
        }
        catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException or InvalidCastException or FormatException or OverflowException) { }
        return letters;
    }

    /// <summary>
    /// Fills a page's save-folder box without blocking the window: <see cref="DefaultSaveFolder"/> at once, then the best
    /// drive when found, unless the person has changed the box in the meantime. Returns every drive found, best first.
    /// </summary>
    public static async Task<List<SaveDrive>> SuggestSaveFolderAsync(Func<string> get, Action<string> set, Func<List<SaveDrive>>? find = null)
    {
        set(DefaultSaveFolder);
        var found = await Task.Run(find ?? FindSaveDrives);
        if (get() == DefaultSaveFolder && found.Count > 0) set(found[0].Root);
        return found;
    }

    /// <summary>
    /// Wires a page's save-folder row: the box (remembered folder, else the best drive), the list of drives found (picking
    /// one fills the box; hidden when none) and the warning shown while the box points at this PC's own drive.
    /// </summary>
    public static async Task AttachSaveFolderAsync(System.Windows.Controls.TextBox box, ComboBox drives, FrameworkElement drivesRow,
        FrameworkElement warning, TextBlock warningText, string? remembered)
    {
        var system = SystemRoot;
        warningText.Text = SystemDriveWarning;
        void Update()
        {
            warning.Visibility = IsOnSystemDrive(box.Text, system, FileIdentity.DosDeviceTarget) ? Visibility.Visible : Visibility.Collapsed;
            var match = (drives.ItemsSource as List<SaveDrive>)?.FirstOrDefault(d => string.Equals(d.Root, box.Text.Trim(), StringComparison.OrdinalIgnoreCase));
            if (!ReferenceEquals(drives.SelectedItem, match)) drives.SelectedItem = match;
        }
        box.TextChanged += (_, _) => Update();
        drives.SelectionChanged += (_, _) => { if (drives.SelectedItem is SaveDrive d && !string.Equals(box.Text.Trim(), d.Root, StringComparison.OrdinalIgnoreCase)) box.Text = d.Root; };
        drivesRow.Visibility = Visibility.Collapsed;

        List<SaveDrive> found;
        if (string.IsNullOrWhiteSpace(remembered)) found = await SuggestSaveFolderAsync(() => box.Text, s => box.Text = s);
        else { box.Text = remembered; found = await Task.Run(FindSaveDrives); }
        drives.ItemsSource = found;
        drivesRow.Visibility = found.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        Update();
    }
}

/// <summary>A drive the results could be saved to, as listed under the save folder.</summary>
public sealed record SaveDrive(string Root, string? Label, long FreeBytes, bool Usb, bool Removable, bool HoldsWindows)
{
    public override string ToString()
    {
        var kind = Usb ? "USB drive" : Removable ? "removable drive" : "drive";
        var name = string.IsNullOrWhiteSpace(Label) ? Root : $"{Root} {Label}";
        return $"{name} ({kind}, {Size(FreeBytes)} free)";
    }

    /// <summary>A size the way File Explorer shows it: 812 GB, 4.5 GB, 700 MB.</summary>
    public static string Size(long bytes)
    {
        const double Gb = 1024d * 1024 * 1024;
        if (bytes >= 1024 * Gb) return (bytes / (1024 * Gb)).ToString(bytes >= 10 * 1024 * Gb ? "0" : "0.#", CultureInfo.InvariantCulture) + " TB";
        if (bytes >= Gb) return (bytes / Gb).ToString(bytes >= 10 * Gb ? "0" : "0.#", CultureInfo.InvariantCulture) + " GB";
        return Math.Max(0, bytes / (1024 * 1024)).ToString(CultureInfo.InvariantCulture) + " MB";
    }
}
