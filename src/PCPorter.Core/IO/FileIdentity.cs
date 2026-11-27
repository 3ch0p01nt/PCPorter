using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PCPorter.Core.IO;

/// <summary>What a folder or file entry itself is (its own attributes and reparse tag, links NOT followed).</summary>
public readonly record struct EntryInfo(FileAttributes Attributes, uint ReparseTag)
{
    const uint NameSurrogateBit = 0x20000000;            // IsReparseTagNameSurrogate: junction, symlink, mount point
    const FileAttributes CloudAttributes = (FileAttributes)(0x40000 | 0x80000 | 0x100000 | 0x400000);   // recall-on-open, pinned, unpinned, recall-on-data-access

    public bool IsReparsePoint => Attributes.HasFlag(FileAttributes.ReparsePoint);

    /// <summary>A junction, symbolic link or mount point: opening it leads somewhere else.</summary>
    public bool IsLink => IsReparsePoint && (ReparseTag & NameSurrogateBit) != 0;

    /// <summary>A cloud-files placeholder or sync root (OneDrive, SharePoint, Google Drive, Dropbox, iCloud ... via the Windows cloud filter).</summary>
    public bool IsCloud => (IsReparsePoint && (ReparseTag & 0xFFFF0FFF) == 0x9000001A) || (Attributes & CloudAttributes) != 0;
}

/// <summary>Real locations and identities of files/folders, for the root guard, the save-folder checks and drive checks.</summary>
public static class FileIdentity
{
    const uint VolumeNameDos = 0x0, VolumeNameNt = 0x2;

    /// <summary>The fully resolved path in drive-letter form (every junction/symlink followed; UNC as \\server\share), or null.</summary>
    public static string? FinalPath(string path)
    {
        using var h = OpenForQuery(path, followLinks: true);
        return h is null ? null : FinalPath(h);
    }

    public static string? FinalPath(SafeFileHandle handle) => Normalize(Query(handle, VolumeNameDos));

    /// <summary>
    /// The fully resolved NT path, e.g. \Device\HarddiskVolume3\Users or \Device\HarddiskVolumeShadowCopy4\Users. Works for
    /// device-path roots that have no drive letter. Null if the path cannot be opened. Follows links: check the chain first.
    /// </summary>
    public static string? NtPath(string path)
    {
        using var h = OpenForQuery(path, followLinks: true);
        return h is null ? null : NtPath(h);
    }

    public static string? NtPath(SafeFileHandle handle) => Query(handle, VolumeNameNt);

    /// <summary>The entry's own attributes and reparse tag (a link is NOT followed), or null if it cannot be opened.</summary>
    public static EntryInfo? Entry(string path)
    {
        using var h = OpenForQuery(path, followLinks: false);
        if (h is null || !GetFileInformationByHandleEx(h, 9 /* FileAttributeTagInfo */, out var info, 8)) return null;
        return new EntryInfo((FileAttributes)info.FileAttributes, info.ReparseTag);
    }

    /// <summary>(volume serial, file index): the same file always has the same pair, whatever path or letter reaches it.</summary>
    public static (uint Volume, ulong File)? Identity(string path)
    {
        using var h = OpenForQuery(path, followLinks: true);
        if (h is null || !GetFileInformationByHandle(h, out var info)) return null;
        return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }

    /// <summary>Number of hard links to the open file, or null.</summary>
    public static uint? LinkCount(SafeFileHandle handle) =>
        GetFileInformationByHandle(handle, out var info) ? info.NumberOfLinks : null;

    /// <summary>True when the volume holding <paramref name="root"/> is mounted read-only.</summary>
    public static bool? IsReadOnlyVolume(string root)
    {
        var r = root.EndsWith('\\') ? root : root + "\\";
        return GetVolumeInformation(r, null, 0, out _, out _, out uint flags, null, 0) ? (flags & 0x80000) != 0 : null;
    }

    /// <summary>Volume label and file system name of a root like E:\ (nulls when unknown).</summary>
    public static (string? Label, string? FileSystem) VolumeInfo(string root)
    {
        var r = root.EndsWith('\\') ? root : root + "\\";
        var label = new StringBuilder(261);
        var fs = new StringBuilder(261);
        return GetVolumeInformation(r, label, label.Capacity, out _, out _, out _, fs, fs.Capacity) ? (label.ToString(), fs.ToString()) : (null, null);
    }

    /// <summary>What a drive letter ("S:") maps to in the object namespace, e.g. \Device\HarddiskVolume3 or \??\C:\Users\bob for subst.</summary>
    public static string? DosDeviceTarget(string driveLetter)
    {
        var buffer = new char[1024];
        uint n = QueryDosDevice(driveLetter.TrimEnd('\\'), buffer, (uint)buffer.Length);
        if (n == 0) return null;
        var end = Array.IndexOf(buffer, '\0');
        return new string(buffer, 0, end < 0 ? (int)n : end);
    }

    static string? Query(SafeFileHandle handle, uint flags)
    {
        var sb = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, flags);
        if (n == 0) return null;
        if (n > sb.Capacity) { sb.Capacity = (int)n + 1; n = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, flags); if (n == 0) return null; }
        return sb.ToString();
    }

    static SafeFileHandle? OpenForQuery(string path, bool followLinks)
    {
        // FILE_READ_ATTRIBUTES works even on files the system holds open (hives); BACKUP_SEMANTICS opens folders;
        // OPEN_REPARSE_POINT opens a link itself instead of what it points to.
        uint flags = 0x02000000 | (followLinks ? 0u : 0x00200000u);
        var h = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, flags, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); return null; }
        return h;
    }

    static string? Normalize(string? p)
    {
        if (p is null) return null;
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + p[8..];
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) && p.Length > 5 && p[5] == ':') return p[4..];
        return p;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes; public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ATTRIBUTE_TAG_INFO { public uint FileAttributes, ReparseTag; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle h, StringBuilder path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out FILE_ATTRIBUTE_TAG_INFO info, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetVolumeInformationW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformation(string root, StringBuilder? name, int nameSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder? fs, int fsSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryDosDeviceW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint QueryDosDevice(string device, [Out] char[] target, uint max);
}
