using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PCPorter.Collectors.Sources;

/// <summary>Real locations and identities of files/folders (follows every link in the path), for the root guard and drive checks.</summary>
public static class FileIdentity
{
    /// <summary>The fully resolved path (every junction/symlink followed), or null if it cannot be opened.</summary>
    public static string? FinalPath(string path)
    {
        using var h = OpenForQuery(path);
        return h is null ? null : FinalPath(h);
    }

    public static string? FinalPath(SafeFileHandle handle)
    {
        var sb = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, 0);
        if (n == 0) return null;
        if (n > sb.Capacity) { sb.Capacity = (int)n + 1; n = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, 0); if (n == 0) return null; }
        return Normalize(sb.ToString());
    }

    /// <summary>(volume serial, file index): the same file always has the same pair, whatever path or letter reaches it.</summary>
    public static (uint Volume, ulong File)? Identity(string path)
    {
        using var h = OpenForQuery(path);
        if (h is null || !GetFileInformationByHandle(h, out var info)) return null;
        return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }

    /// <summary>True when the volume holding <paramref name="root"/> is mounted read-only.</summary>
    public static bool? IsReadOnlyVolume(string root)
    {
        var r = root.EndsWith('\\') ? root : root + "\\";
        return GetVolumeInformation(r, null, 0, out _, out _, out uint flags, null, 0) ? (flags & 0x80000) != 0 : null;
    }

    static SafeFileHandle? OpenForQuery(string path)
    {
        // FILE_READ_ATTRIBUTES works even on files the system holds open (hives); BACKUP_SEMANTICS opens folders.
        var h = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); return null; }
        return h;
    }

    static string Normalize(string p)
    {
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetVolumeInformationW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformation(string root, StringBuilder? name, int nameSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder? fs, int fsSize);
}
