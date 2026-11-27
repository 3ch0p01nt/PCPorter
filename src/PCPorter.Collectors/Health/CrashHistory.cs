using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Health;

/// <summary>One event as needed here: when, and its first data value (for WER 1001: the bugcheck text).</summary>
public sealed record EventRow(DateTimeOffset When, string? FirstData);

/// <summary>Reads events: <paramref name="logOrFile"/> is a channel name when <paramref name="isFile"/> is false, else an .evtx path.</summary>
public delegate IReadOnlyList<EventRow> EventQuery(string logOrFile, bool isFile, string xpath, int max);

/// <summary>Bugchecks (WER 1001), unexpected shutdowns (Kernel-Power 41) and minidumps, live or from the old drive's System.evtx.</summary>
public static class CrashHistory
{
    public const int Days = 90;
    const long NinetyDaysMs = Days * 24L * 3600 * 1000;

    public static readonly string BugCheckXPath =
        $"*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001 and TimeCreated[timediff(@SystemTime) <= {NinetyDaysMs}]]]";
    public static readonly string KernelPowerXPath =
        $"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41 and TimeCreated[timediff(@SystemTime) <= {NinetyDaysMs}]]]";

    public static CrashSummary? Read(ISystemSource src, EventQuery query, IList<string> warnings, IDictionary<string, string> unknown, DateTimeOffset now)
    {
        string logOrFile;
        bool isFile;
        if (src.IsLive) { logOrFile = "System"; isFile = false; }
        else
        {
            var mapped = src.MapPath(src.OriginalSystemDrive + @"\Windows\System32\winevt\Logs\System.evtx");
            if (mapped is null || !File.Exists(mapped))
            {
                warnings.Add("Profile: the old PC's System event log was not found; crash history is unknown.");
                logOrFile = "";
                isFile = true;
            }
            else { logOrFile = mapped; isFile = true; }
        }

        IReadOnlyList<CrashEvent>? bugchecks = null;
        int? shutdowns = null;
        if (logOrFile.Length > 0)
        {
            try
            {
                bugchecks = ParseBugChecks(query(logOrFile, isFile, BugCheckXPath, 500), now);
                shutdowns = query(logOrFile, isFile, KernelPowerXPath, 10_000).Count(e => e.When >= now.AddDays(-Days));
            }
            catch (UnauthorizedAccessException) { unknown["crashes"] = PcProfile.NotElevated; }
            catch (Exception e) when (e is Win32Exception or IOException or EventQueryException)
            {
                warnings.Add($"Profile: System event log could not be read: {e.Message}");
            }
        }

        var (count, newest) = Minidumps(src, unknown);
        if (bugchecks is null && shutdowns is null && count is null) return null;
        return new CrashSummary(bugchecks ?? [], shutdowns, count, newest, src.IsLive ? "live System log" : "System.evtx on the old drive");
    }

    /// <summary>Bugchecks within the last 90 days, newest first; code from the first data value ("0x0000001e (0x...)" => "0x0000001e").</summary>
    public static IReadOnlyList<CrashEvent> ParseBugChecks(IEnumerable<EventRow> rows, DateTimeOffset now) =>
        rows.Where(r => r.When >= now.AddDays(-Days))
            .OrderByDescending(r => r.When)
            .Select(r => new CrashEvent(r.When, BugCheckCode(r.FirstData)))
            .ToList();

    public static string? BugCheckCode(string? data)
    {
        if (string.IsNullOrWhiteSpace(data)) return null;
        var first = data.Trim().Split([' ', '(', ','], 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrEmpty(first) ? null : first;
    }

    /// <summary>Windows\Minidump\*.dmp count and newest write time; null + "not elevated" when the folder cannot be listed.</summary>
    public static (int? Count, DateTimeOffset? Newest) Minidumps(ISystemSource src, IDictionary<string, string> unknown)
    {
        var dir = src.MapPath(src.OriginalSystemDrive + @"\Windows\Minidump");
        if (dir is null) return (null, null);
        if (!Directory.Exists(dir)) return (0, null);
        try
        {
            var opts = new EnumerationOptions { IgnoreInaccessible = false, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false };
            var files = Directory.EnumerateFiles(dir, "*.dmp", opts).Select(f => new FileInfo(f)).ToList();
            DateTimeOffset? newest = files.Count == 0 ? null : new DateTimeOffset(files.Max(f => f.LastWriteTimeUtc), TimeSpan.Zero);
            return (files.Count, newest);
        }
        catch (UnauthorizedAccessException) { unknown["minidumps"] = PcProfile.NotElevated; return (null, null); }
        catch (IOException) { return (null, null); }
    }

    // ---- Reading events through wevtapi.dll (in-box; System.Diagnostics.Eventing.Reader is not referenced by this project) ----

    public sealed class EventQueryException(string message) : Exception(message);

    /// <summary>Default <see cref="EventQuery"/>: EvtQuery/EvtNext/EvtRender, newest first, read-only.</summary>
    public static IReadOnlyList<EventRow> QueryEvents(string logOrFile, bool isFile, string xpath, int max)
    {
        var rows = new List<EventRow>();
        var flags = (isFile ? EvtQueryFilePath : EvtQueryChannelPath) | EvtQueryReverseDirection;
        using var query = EvtQuery(IntPtr.Zero, logOrFile, xpath, flags);
        if (query.IsInvalid) ThrowLast("EvtQuery");
        var handles = new IntPtr[64];
        while (rows.Count < max)
        {
            if (!EvtNext(query, handles.Length, handles, 5000, 0, out var returned))
            {
                var err = Marshal.GetLastWin32Error();
                if (err is ERROR_NO_MORE_ITEMS) break;
                if (err is ERROR_TIMEOUT) break;
                ThrowFor(err, "EvtNext");
            }
            for (int i = 0; i < returned; i++)
            {
                try { if (rows.Count < max && Render(handles[i]) is { } row) rows.Add(row); }
                finally { EvtClose(handles[i]); }
            }
        }
        return rows;
    }

    static EventRow? Render(IntPtr evt)
    {
        EvtRender(IntPtr.Zero, evt, EvtRenderEventXml, 0, null, out var used, out _);
        var err = Marshal.GetLastWin32Error();
        if (err != ERROR_INSUFFICIENT_BUFFER || used <= 0) return null;
        var buffer = new byte[used];
        if (!EvtRender(IntPtr.Zero, evt, EvtRenderEventXml, used, buffer, out used, out _)) return null;
        var xml = Encoding.Unicode.GetString(buffer, 0, Math.Max(0, used - 2)).TrimEnd('\0');
        return ParseEventXml(xml);
    }

    /// <summary>Event XML => time and first EventData value.</summary>
    public static EventRow? ParseEventXml(string xml)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { return null; }
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var t = doc.Root?.Element(ns + "System")?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (t is null || !DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var when)) return null;
        var first = doc.Root?.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault()?.Value;
        return new EventRow(when, first);
    }

    static void ThrowLast(string what) => ThrowFor(Marshal.GetLastWin32Error(), what);

    static void ThrowFor(int err, string what)
    {
        if (err == ERROR_ACCESS_DENIED) throw new UnauthorizedAccessException($"{what}: access denied.");
        throw new EventQueryException($"{what} failed: {new Win32Exception(err).Message} ({err}).");
    }

    const int EvtQueryChannelPath = 0x1, EvtQueryFilePath = 0x2, EvtQueryReverseDirection = 0x200;
    const int EvtRenderEventXml = 1;
    const int ERROR_ACCESS_DENIED = 5, ERROR_INSUFFICIENT_BUFFER = 122, ERROR_NO_MORE_ITEMS = 259, ERROR_TIMEOUT = 1460;

    sealed class EvtHandle() : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => EvtClose(handle);
    }

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern EvtHandle EvtQuery(IntPtr session, string path, string query, int flags);

    [DllImport("wevtapi.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool EvtNext(EvtHandle resultSet, int eventArraySize, [Out] IntPtr[] eventArray, int timeout, int flags, out int returned);

    [DllImport("wevtapi.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool EvtRender(IntPtr context, IntPtr fragment, int flags, int bufferSize, [Out] byte[]? buffer, out int bufferUsed, out int propertyCount);

    [DllImport("wevtapi.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool EvtClose(IntPtr handle);
}
