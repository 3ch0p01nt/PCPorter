using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Offline;

/// <param name="Hibernated">hiberfil.sys has a HIBR/hibr header; null if it could not be read.</param>
/// <param name="Dirty">NTFS dirty bit; null if it could not be queried (usually: not elevated).</param>
/// <param name="NextUsn">NTFS change journal position; null if unavailable.</param>
public sealed record VolumeSafetyReport(bool? Hibernated, bool? Dirty, long? NextUsn)
{
    public const string UncleanWarning = "This PC was hibernated or not shut down cleanly - do not let it resume after this.";
    public string? Warning => Hibernated == true || Dirty == true ? UncleanWarning : null;
}

/// <summary>Read-only safety checks on another PC's drive (dead-PC mode). Every check is best-effort.</summary>
public static class VolumeSafety
{
    public static VolumeSafetyReport Check(string root) => new(IsHibernated(root), IsDirty(root), NextUsn(root));

    /// <summary>
    /// True when <c>&lt;root&gt;hiberfil.sys</c> starts with "HIBR" or "hibr" (a resumable hibernation image).
    /// False when the file is missing or has another header; null when it cannot be read.
    /// </summary>
    public static bool? IsHibernated(string root)
    {
        var file = Path.Combine(root, "hiberfil.sys");
        try
        {
            using var confine = SourceFiles.Confine(root);   // a link planted in its place is never followed
            switch (SourcePresence.Of(file))
            {
                case Presence.Missing: return false;
                case Presence.NotFollowed: return null;
            }
            if (!File.Exists(file)) return false;
            using var stream = SourceFiles.OpenRead(file);
            Span<byte> header = stackalloc byte[4];
            if (stream.ReadAtLeast(header, 4, throwOnEndOfStream: false) < 4) return false;
            return header.SequenceEqual("HIBR"u8) || header.SequenceEqual("hibr"u8);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>A change between two journal positions means something wrote to the drive during the scan.</summary>
    public static string? UsnChangeWarning(long? before, long? after) =>
        before is { } b && after is { } a && a != b
            ? "The drive's change journal moved during the scan: something (not PCPorter) wrote to it. Attach it read-only next time."
            : null;

    /// <summary>FSCTL_IS_VOLUME_DIRTY on \\.\X:. Null on any failure (not elevated, not NTFS, not a drive letter).</summary>
    public static bool? IsDirty(string root)
    {
        using var volume = OpenVolume(root);
        if (volume is null) return null;
        var output = new byte[4];
        if (!DeviceIoControl(volume, FSCTL_IS_VOLUME_DIRTY, IntPtr.Zero, 0, output, (uint)output.Length, out var returned, IntPtr.Zero) || returned < 4)
            return null;
        return (BinaryPrimitives.ReadUInt32LittleEndian(output) & VOLUME_IS_DIRTY) != 0;
    }

    /// <summary>NextUsn from FSCTL_QUERY_USN_JOURNAL on \\.\X:. Null on any failure (no journal, not elevated...).</summary>
    public static long? NextUsn(string root)
    {
        using var volume = OpenVolume(root);
        if (volume is null) return null;
        var output = new byte[80];   // USN_JOURNAL_DATA_V1; NextUsn is at offset 16 in V0 and V1
        if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, output, (uint)output.Length, out var returned, IntPtr.Zero) || returned < 24)
            return null;
        return BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(16));
    }

    /// <summary>"D:\" => \\.\D: opened for reading only (no write access is ever requested).</summary>
    static SafeFileHandle? OpenVolume(string root)
    {
        var normalized = OfflineVolumeFinder.NormalizeRoot(root);
        if (normalized is not { Length: 3 }) return null;   // drive letters only
        var handle = CreateFile(@"\\.\" + normalized[..2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); return null; }
        return handle;
    }

    const uint FSCTL_IS_VOLUME_DIRTY = 0x00090078;       // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;     // CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
    const uint VOLUME_IS_DIRTY = 0x1;
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2, FILE_SHARE_DELETE = 0x4;
    const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize,
        [Out] byte[] lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);
}
