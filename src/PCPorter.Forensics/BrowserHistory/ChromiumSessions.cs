using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Reads open and recently closed tabs from a Chromium profile's session files (SNSS command logs):
/// <c>Sessions\Session_*</c> (open windows and tabs, older <c>Current Session</c> / <c>Last Session</c>) and
/// <c>Sessions\Tabs_*</c> (the "recently closed" list, older <c>Current Tabs</c> / <c>Last Tabs</c>).
/// Each file is a header ("SNSS" + int32 version) followed by records of uint16 size, uint8 command id and payload.
/// Unknown commands are skipped; a record that runs past the end of the file (the browser was still writing) ends
/// parsing with a note.
/// </summary>
public static class ChromiumSessions
{
    // Session service commands (session_service_commands.cc).
    const byte SetTabWindow = 0, UpdateTabNavigation = 6, SetSelectedNavigationIndex = 7, TabClosed = 16, WindowClosed = 17, LastActiveTime = 21;
    // Tab restore service commands (tab_restore_service_impl.cc).
    const byte RestoreUpdateTabNavigation = 1, RestoreSelectedNavigationInTab = 4;

    const long FileCap = 64L << 20;

    /// <summary>
    /// Reads the newest session file and the newest tabs file. A running browser may hold its current file without
    /// sharing it; then the previous file (which Chromium keeps next to it) is read instead, with a note. Throws when
    /// files exist but none can be read.
    /// </summary>
    public static List<OpenTab> Read(BrowserProfile profile, List<string> notes)
    {
        var tabs = ReadFirst(profile, Candidates(profile.Folder, "Session_", "Current Session", "Last Session"), restoreList: false, notes);
        tabs.AddRange(ReadFirst(profile, Candidates(profile.Folder, "Tabs_", "Current Tabs", "Last Tabs"), restoreList: true, notes));
        return tabs;
    }

    static List<OpenTab> ReadFirst(BrowserProfile profile, List<string> files, bool restoreList, List<string> notes)
    {
        IOException? locked = null;
        foreach (var file in files)
        {
            byte[] bytes;
            try { bytes = SourceFiles.ReadAllBytes(file, FileCap); }
            catch (IOException e) when (IsLocked(e)) { locked ??= e; continue; }
            if (locked is not null)
                notes.Add($"The current {(restoreList ? "recently closed tabs" : "session")} file of {profile.Browser} ({profile.Name}) for {profile.User} " +
                          "is in use by the running browser, so the tabs shown come from the previous file.");
            return Parse(profile, bytes, restoreList, notes);
        }
        if (locked is not null) throw locked;
        return [];
    }

    /// <summary>Sharing or lock violation (the browser has the file open without sharing it).</summary>
    static bool IsLocked(IOException e) => (e.HResult & 0xFFFF) is 32 or 33;

    /// <summary><c>Sessions\{prefix}&lt;time&gt;</c> files newest first, then the older-style files that exist.</summary>
    static List<string> Candidates(string folder, string prefix, params string[] older) =>
        SourceFiles.Files(Path.Combine(folder, "Sessions"), prefix + "*")
            .Select(f => (Path: f, Stamp: long.TryParse(Path.GetFileName(f)[prefix.Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : -1))
            .Where(f => f.Stamp >= 0 && BrowserProfileFinder.FileExists(f.Path))
            .OrderByDescending(f => f.Stamp)
            .Select(f => f.Path)
            .Concat(older.Select(o => Path.Combine(folder, o)).Where(BrowserProfileFinder.FileExists))
            .ToList();

    sealed class Tab
    {
        public readonly SortedDictionary<int, (string Url, string Title)> Navigations = [];
        public int? Selected;
        public int? Window;
        public DateTimeOffset? LastActive;
        public DateTimeOffset? Closed;
        public int Order;
    }

    /// <param name="restoreList">True for a Tabs_ file: every tab in it was recently closed.</param>
    public static List<OpenTab> Parse(BrowserProfile profile, ReadOnlySpan<byte> file, bool restoreList, List<string> notes)
    {
        var what = $"{profile.Browser} ({profile.Name}) for {profile.User}";
        if (file.Length < 8 || !file[..4].SequenceEqual("SNSS"u8))
        {
            notes.Add($"A session file of {what} is not in the expected format; its tabs were not read.");
            return [];
        }
        int version = BinaryPrimitives.ReadInt32LittleEndian(file[4..]);
        if (version is not (1 or 3))
        {
            notes.Add($"A session file of {what} uses a format this version of PCPorter cannot read (version {version}); its tabs were not read.");
            return [];
        }

        var tabs = new Dictionary<int, Tab>();
        var windows = new Dictionary<int, int>();          // window id -> 1, 2, ... in order of appearance
        var closedWindows = new Dictionary<int, DateTimeOffset?>();
        Tab Get(int id) { if (!tabs.TryGetValue(id, out var t)) tabs[id] = t = new Tab { Order = tabs.Count }; return t; }

        int pos = 8;
        while (pos < file.Length)
        {
            if (file.Length - pos < 2) { CutShort(notes, what); break; }
            int size = BinaryPrimitives.ReadUInt16LittleEndian(file[pos..]);
            pos += 2;
            if (size == 0 || size > file.Length - pos) { CutShort(notes, what); break; }
            byte id = file[pos];
            var payload = file.Slice(pos + 1, size - 1);
            pos += size;

            if (restoreList)
            {
                if (id == RestoreUpdateTabNavigation && Navigation(payload) is { } rn) Get(rn.Tab).Navigations[rn.Index] = (rn.Url, rn.Title);
                else if (id == RestoreSelectedNavigationInTab && payload.Length >= 8)
                {
                    var t = Get(Int(payload, 0));
                    t.Selected = Int(payload, 4);
                    if (payload.Length >= 16) t.Closed = Timestamps.FromWebKit(BinaryPrimitives.ReadInt64LittleEndian(payload[8..]));
                }
                continue;
            }

            switch (id)
            {
                case SetTabWindow when payload.Length >= 8:
                {
                    int window = Int(payload, 0);
                    if (!windows.ContainsKey(window)) windows[window] = windows.Count + 1;
                    Get(Int(payload, 4)).Window = window;
                    break;
                }
                case UpdateTabNavigation when Navigation(payload) is { } n:
                    Get(n.Tab).Navigations[n.Index] = (n.Url, n.Title);
                    break;
                case SetSelectedNavigationIndex when payload.Length >= 8:
                    Get(Int(payload, 0)).Selected = Int(payload, 4);
                    break;
                case TabClosed when payload.Length >= 4:
                    Get(Int(payload, 0)).Closed = Time(payload) ?? DateTimeOffset.MinValue;
                    break;
                case WindowClosed when payload.Length >= 4:
                    closedWindows[Int(payload, 0)] = Time(payload);
                    break;
                case LastActiveTime when payload.Length >= 16:
                    Get(Int(payload, 0)).LastActive = Time(payload);
                    break;
            }
        }

        var result = new List<OpenTab>();
        foreach (var t in tabs.Values.OrderBy(t => t.Order))
        {
            if (t.Navigations.Count == 0) continue;
            var (url, title) = t.Selected is { } s && t.Navigations.TryGetValue(s, out var sel) ? sel : t.Navigations.Last().Value;
            if (url.Length == 0) continue;
            DateTimeOffset? windowClosed = null;
            bool closed = restoreList || t.Closed is not null || (t.Window is { } w && closedWindows.TryGetValue(w, out windowClosed));
            var closedAt = t.Closed == DateTimeOffset.MinValue ? null : t.Closed;
            result.Add(new OpenTab(profile, Redactor.Redact(url), title.Length == 0 ? null : Redactor.Redact(title),
                t.Window is { } win && windows.TryGetValue(win, out var number) ? number : 0,
                closed ? TabState.RecentlyClosed : TabState.Open,
                t.LastActive ?? closedAt ?? windowClosed));
        }
        return result;
    }

    static void CutShort(List<string> notes, string what) =>
        notes.Add($"A session file of {what} ends part-way through a record (the browser was probably still writing it); the tabs before that point were read.");

    static int Int(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadInt32LittleEndian(b[at..]);

    /// <summary>Close / last-active payloads: int32 id, 4 bytes padding, int64 time (WebKit microseconds).</summary>
    static DateTimeOffset? Time(ReadOnlySpan<byte> payload) =>
        payload.Length >= 16 ? Timestamps.FromWebKit(BinaryPrimitives.ReadInt64LittleEndian(payload[8..])) : null;

    /// <summary>
    /// A tab navigation, stored as a Pickle: uint32 payload size, int32 tab id, int32 index, string url (int32 length +
    /// bytes), string16 title (int32 length in UTF-16 units + data); every field is padded to 4 bytes.
    /// </summary>
    static (int Tab, int Index, string Url, string Title)? Navigation(ReadOnlySpan<byte> pickle)
    {
        if (pickle.Length < 4) return null;
        int declared = BinaryPrimitives.ReadInt32LittleEndian(pickle);
        var body = pickle[4..];
        if (declared >= 0 && declared < body.Length) body = body[..declared];
        int at = 0;
        if (!ReadInt(body, ref at, out var tab) || !ReadInt(body, ref at, out var index)) return null;
        if (!ReadInt(body, ref at, out var urlLength) || urlLength < 0 || urlLength > body.Length - at) return null;
        var url = Encoding.UTF8.GetString(body.Slice(at, urlLength));
        at += Align(urlLength);
        string title = "";
        if (at <= body.Length && ReadInt(body, ref at, out var titleChars) && titleChars >= 0 && titleChars <= (body.Length - at) / 2)
            title = Encoding.Unicode.GetString(body.Slice(at, titleChars * 2));
        return (tab, index, url, title);
    }

    static bool ReadInt(ReadOnlySpan<byte> b, ref int at, out int value)
    {
        value = 0;
        if (at < 0 || b.Length - at < 4) return false;
        value = BinaryPrimitives.ReadInt32LittleEndian(b[at..]);
        at += 4;
        return true;
    }

    static int Align(int n) => (n + 3) & ~3;
}
