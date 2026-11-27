using System.Runtime.InteropServices;

namespace PCPorter.Collectors.Health;

/// <summary>A monitor as the display APIs see it. DevicePath joins it to WmiMonitorID.</summary>
public sealed record NativeMonitor(string? FriendlyName, int? Width, int? Height, int? ScalePercent, string? DevicePath);

/// <summary>
/// Active monitors via QueryDisplayConfig + DisplayConfigGetDeviceInfo (friendly name, resolution) and GetDpiForMonitor (scale).
/// Live only; read-only queries. Never throws (returns what it could read).
/// </summary>
public static class DisplayInfo
{
    public static IReadOnlyList<NativeMonitor> Query(IList<string>? warnings = null)
    {
        try { return QueryCore(); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or ExternalException or InvalidOperationException)
        {
            warnings?.Add($"Profile: monitors could not be read: {e.Message}");
            return [];
        }
    }

    static List<NativeMonitor> QueryCore()
    {
        DISPLAYCONFIG_PATH_INFO[] paths = [];
        DISPLAYCONFIG_MODE_INFO[] modes = [];
        int rc = ERROR_INSUFFICIENT_BUFFER;
        for (int attempt = 0; attempt < 5 && rc == ERROR_INSUFFICIENT_BUFFER; attempt++)
        {
            rc = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, out var pathCount, out var modeCount);
            if (rc == ERROR_ACCESS_DENIED) return [];   // see below
            if (rc != 0) throw new InvalidOperationException($"GetDisplayConfigBufferSizes returned {rc}.");
            paths = new DISPLAYCONFIG_PATH_INFO[pathCount];
            modes = new DISPLAYCONFIG_MODE_INFO[modeCount];
            rc = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, ref pathCount, paths, ref modeCount, modes, IntPtr.Zero);
            if (rc == 0) { Array.Resize(ref paths, (int)pathCount); Array.Resize(ref modes, (int)modeCount); }
        }
        // ERROR_ACCESS_DENIED: no access to the visible desktop (run as a scheduled task, or the session is locked or
        // disconnected). Not a scan failure: there are no monitors to list, and WMI still names the connected ones.
        if (rc == ERROR_ACCESS_DENIED) return [];
        if (rc != 0) throw new InvalidOperationException($"QueryDisplayConfig returned {rc}.");

        var dpiByGdiName = MonitorDpis();
        var list = new List<NativeMonitor>();
        foreach (var path in paths)
        {
            var target = new DISPLAYCONFIG_TARGET_DEVICE_NAME
            {
                header = new DISPLAYCONFIG_DEVICE_INFO_HEADER
                {
                    type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME, size = (uint)Marshal.SizeOf<DISPLAYCONFIG_TARGET_DEVICE_NAME>(),
                    adapterId = path.targetInfo.adapterId, id = path.targetInfo.id,
                },
            };
            string? friendly = null, devicePath = null;
            if (DisplayConfigGetDeviceInfo(ref target) == 0)
            {
                friendly = string.IsNullOrWhiteSpace(target.monitorFriendlyDeviceName) ? null : target.monitorFriendlyDeviceName.Trim();
                devicePath = string.IsNullOrWhiteSpace(target.monitorDevicePath) ? null : target.monitorDevicePath;
            }

            var source = new DISPLAYCONFIG_SOURCE_DEVICE_NAME
            {
                header = new DISPLAYCONFIG_DEVICE_INFO_HEADER
                {
                    type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME, size = (uint)Marshal.SizeOf<DISPLAYCONFIG_SOURCE_DEVICE_NAME>(),
                    adapterId = path.sourceInfo.adapterId, id = path.sourceInfo.id,
                },
            };
            int? scale = null;
            if (DisplayConfigGetDeviceInfo(ref source) == 0 && dpiByGdiName.TryGetValue(source.viewGdiDeviceName ?? "", out var dpi)) scale = dpi;

            int? w = null, h = null;
            var idx = path.sourceInfo.modeInfoIdx;
            if (idx != DISPLAYCONFIG_PATH_MODE_IDX_INVALID && idx < modes.Length && modes[idx].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE)
            {
                w = (int)modes[idx].sourceWidth;
                h = (int)modes[idx].sourceHeight;
            }
            list.Add(new NativeMonitor(friendly, w, h, scale, devicePath));
        }
        return list;
    }

    /// <summary>GDI device name ("\\.\DISPLAY1") -> scale percent (effective DPI * 100 / 96), read per-monitor-DPI-aware.</summary>
    static Dictionary<string, int> MonitorDpis()
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        IntPtr previous = IntPtr.Zero;
        try { previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); }
        catch (EntryPointNotFoundException) { }
        try
        {
            MonitorEnumProc cb = (hMon, _, _, _) =>
            {
                var info = new MONITORINFOEX { cbSize = (uint)Marshal.SizeOf<MONITORINFOEX>() };
                if (GetMonitorInfoW(hMon, ref info) && GetDpiForMonitor(hMon, MDT_EFFECTIVE_DPI, out var dx, out _) == 0 && dx > 0)
                    result[info.szDevice ?? ""] = (int)Math.Round(dx * 100.0 / 96.0, MidpointRounding.AwayFromZero);
                return true;
            };
            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, cb, IntPtr.Zero);
            GC.KeepAlive(cb);
        }
        finally
        {
            if (previous != IntPtr.Zero) SetThreadDpiAwarenessContext(previous);
        }
        return result;
    }

    // ---- Win32 ----
    const uint QDC_ONLY_ACTIVE_PATHS = 0x2;
    const int ERROR_INSUFFICIENT_BUFFER = 122;
    const int ERROR_ACCESS_DENIED = 5;
    const uint DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME = 1;
    const uint DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME = 2;
    const uint DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE = 1;
    const uint DISPLAYCONFIG_PATH_MODE_IDX_INVALID = 0xFFFFFFFF;
    const int MDT_EFFECTIVE_DPI = 0;
    static readonly IntPtr DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = new(-4);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct DISPLAYCONFIG_PATH_SOURCE_INFO { public LUID adapterId; public uint id; public uint modeInfoIdx; public uint statusFlags; }

    [StructLayout(LayoutKind.Sequential)]
    struct DISPLAYCONFIG_RATIONAL { public uint Numerator; public uint Denominator; }

    [StructLayout(LayoutKind.Sequential)]
    struct DISPLAYCONFIG_PATH_TARGET_INFO
    {
        public LUID adapterId; public uint id; public uint modeInfoIdx; public uint outputTechnology; public uint rotation; public uint scaling;
        public DISPLAYCONFIG_RATIONAL refreshRate; public uint scanLineOrdering; public int targetAvailable; public uint statusFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DISPLAYCONFIG_PATH_INFO { public DISPLAYCONFIG_PATH_SOURCE_INFO sourceInfo; public DISPLAYCONFIG_PATH_TARGET_INFO targetInfo; public uint flags; }

    /// <summary>64 bytes; only the source-mode part of the union is read.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 64)]
    struct DISPLAYCONFIG_MODE_INFO
    {
        [FieldOffset(0)] public uint infoType;
        [FieldOffset(4)] public uint id;
        [FieldOffset(8)] public LUID adapterId;
        [FieldOffset(16)] public uint sourceWidth;
        [FieldOffset(20)] public uint sourceHeight;
        [FieldOffset(24)] public uint pixelFormat;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DISPLAYCONFIG_DEVICE_INFO_HEADER { public uint type; public uint size; public LUID adapterId; public uint id; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct DISPLAYCONFIG_TARGET_DEVICE_NAME
    {
        public DISPLAYCONFIG_DEVICE_INFO_HEADER header;
        public uint flags; public uint outputTechnology; public ushort edidManufactureId; public ushort edidProductCodeId; public uint connectorInstance;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string monitorFriendlyDeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string monitorDevicePath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct DISPLAYCONFIG_SOURCE_DEVICE_NAME
    {
        public DISPLAYCONFIG_DEVICE_INFO_HEADER header;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string viewGdiDeviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MONITORINFOEX
    {
        public uint cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }

    delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, IntPtr lprcMonitor, IntPtr data);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int GetDisplayConfigBufferSizes(uint flags, out uint numPathArrayElements, out uint numModeInfoArrayElements);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int QueryDisplayConfig(uint flags, ref uint numPathArrayElements, [Out] DISPLAYCONFIG_PATH_INFO[] pathArray,
        ref uint numModeInfoArrayElements, [Out] DISPLAYCONFIG_MODE_INFO[] modeInfoArray, IntPtr currentTopologyId);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int DisplayConfigGetDeviceInfo(ref DISPLAYCONFIG_TARGET_DEVICE_NAME requestPacket);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int DisplayConfigGetDeviceInfo(ref DISPLAYCONFIG_SOURCE_DEVICE_NAME requestPacket);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFOEX lpmi);

    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);

    [DllImport("shcore.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int GetDpiForMonitor(IntPtr hmonitor, int dpiType, out uint dpiX, out uint dpiY);
}
