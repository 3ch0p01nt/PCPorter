using System.Buffers.Binary;
using System.Text;
using Microsoft.Data.Sqlite;
using PCPorter.Core.Security;
using PCPorter.Core.Time;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// Recovers deleted history rows from the raw bytes of a browser's SQLite database and its write-ahead log: free space
/// inside table pages (freeblocks and the gap before the cell content), pages on the freelist, and older versions of
/// pages (main-file pages that the log replaces, and log frames that a later committed frame replaces). A candidate
/// is kept only when it decodes cleanly against the table's own column layout (serial types, an http/https/ftp/file
/// address, a time between 2000 and tomorrow) and is not already in the live database. Rows that continued on
/// overflow pages are skipped and counted. Works on bytes only; nothing is written anywhere. Leftover bytes do not
/// prove a deletion (SQLite also leaves old copies when it moves or updates a row), so rows are labelled
/// "recovered from leftover data", never "deleted".
/// </summary>
public static class SqliteCarver
{
    /// <param name="Spilled">Deleted rows that were too long to recover (their end was on another page).</param>
    public sealed record Result(IReadOnlyList<Visit> Visits, int Spilled);

    static readonly DateTimeOffset Earliest = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal const string FreeSpace = "free space", OlderCopy = "earlier page version";

    public static Result Chromium(BrowserProfile profile, byte[]? main, byte[]? wal, SqliteConnection? live, DateTimeOffset now, CancellationToken ct = default)
    {
        var urls = Layout.FromSchema(live, "urls", Role.Urls, new()
        {
            ["id"] = Kind.RowidNull, ["url"] = Kind.Text, ["title"] = Kind.TextOrNull, ["visit_count"] = Kind.Int,
            ["typed_count"] = Kind.Int, ["last_visit_time"] = Kind.Int, ["hidden"] = Kind.Int,
        }, url: "url", title: "title", time: "last_visit_time", hidden: "hidden");
        var visits = Layout.FromSchema(live, "visits", Role.Visits, new()
        {
            ["id"] = Kind.RowidNull, ["url"] = Kind.Int, ["visit_time"] = Kind.Int, ["from_visit"] = Kind.IntOrNull,
            ["transition"] = Kind.Int, ["visit_duration"] = Kind.Int, ["external_referrer_url"] = Kind.TextOrNull,
            ["segment_id"] = Kind.IntOrNull, ["incremented_omnibox_typed_score"] = Kind.Int, ["opener_visit"] = Kind.IntOrNull,
            ["originator_cache_guid"] = Kind.TextOrNull, ["originator_visit_id"] = Kind.IntOrNull, ["originator_from_visit"] = Kind.IntOrNull,
            ["originator_opener_visit"] = Kind.IntOrNull, ["is_known_to_sync"] = Kind.Int, ["consider_for_ntp_most_visited"] = Kind.Int,
            ["visited_link_id"] = Kind.Int, ["app_id"] = Kind.TextOrNull,
        }, reference: "url", time: "visit_time", kind: "transition", duration: "visit_duration");
        var index = LiveIndex.Read(live, "SELECT id, url, title FROM urls",
            "SELECT v.id, v.visit_time, u.url FROM visits v LEFT JOIN urls u ON u.id = v.url");
        // Chrome stores every navigation with chain-start/end or redirect qualifier bits, so a visit row without any
        // (e.g. old bytes that were partly zeroed) is not taken as one.
        var engine = new Engine([.. new[] { urls, visits }.OfType<Layout>()], Timestamps.FromWebKit,
            transition => transition is >= int.MinValue and <= uint.MaxValue && ((uint)transition & 0xFF) <= 10 && ((uint)transition & 0xF0000000) != 0,
            now, index);
        Walk(main, wal, engine, ct);
        return Assemble(profile, engine, index, Timestamps.FromWebKit,
            t => ChromiumHistoryReader.MapTransition(unchecked((uint)t)), micros => Math.Max(0, micros / 1_000_000));
    }

    public static Result Firefox(BrowserProfile profile, byte[]? main, byte[]? wal, SqliteConnection? live, DateTimeOffset now, CancellationToken ct = default)
    {
        var places = Layout.FromSchema(live, "moz_places", Role.Urls, new()
        {
            ["id"] = Kind.RowidNull, ["url"] = Kind.Text, ["title"] = Kind.TextOrNull, ["rev_host"] = Kind.TextOrNull,
            ["visit_count"] = Kind.IntOrNull, ["hidden"] = Kind.Int, ["typed"] = Kind.Int, ["frecency"] = Kind.Int,
            ["last_visit_date"] = Kind.IntOrNull, ["guid"] = Kind.TextOrNull, ["foreign_count"] = Kind.Int, ["url_hash"] = Kind.Int,
        }, url: "url", title: "title", time: "last_visit_date", hidden: "hidden", revHost: "rev_host");
        var visits = Layout.FromSchema(live, "moz_historyvisits", Role.Visits, new()
        {
            ["id"] = Kind.RowidNull, ["from_visit"] = Kind.IntOrNull, ["place_id"] = Kind.Int, ["visit_date"] = Kind.Int,
            ["visit_type"] = Kind.Int, ["session"] = Kind.IntOrNull,
        }, reference: "place_id", time: "visit_date", kind: "visit_type");
        var index = LiveIndex.Read(live, "SELECT id, url, title FROM moz_places",
            "SELECT v.id, v.visit_date, p.url FROM moz_historyvisits v LEFT JOIN moz_places p ON p.id = v.place_id");
        var engine = new Engine([.. new[] { places, visits }.OfType<Layout>()], Timestamps.FromPRTime,
            type => type is >= 1 and <= 9, now, index);
        Walk(main, wal, engine, ct);
        return Assemble(profile, engine, index, Timestamps.FromPRTime,
            t => FirefoxHistoryReader.MapVisitType((int)t, false), _ => 0);
    }

    /// <summary>What a recovered row is labelled: the bytes were left over, which does not prove the visit was deleted.</summary>
    public const string Label = "Recovered from leftover data";

    /// <summary>The notes a reader adds for what the carver found, one per place the rows came from.</summary>
    internal static void Describe(BrowserProfile profile, Result r, List<string> notes)
    {
        var who = $"{profile.Browser} ({profile.Name}) for {profile.User}";
        static string Visits(int n) => $"{n} visit{(n == 1 ? " was" : "s were")}";
        var free = r.Visits.Count(v => v.OriginNote == FreeSpace);
        var older = r.Visits.Count(v => v.OriginNote == OlderCopy);
        if (free > 0)
            notes.Add($"{who}: {Visits(free)} recovered from leftover data in the free space of the history file (marked \"{Label}\"). " +
                      "Such rows may have been deleted, or be an older copy of a visit the browser moved or changed.");
        if (older > 0)
            notes.Add($"{who}: {Visits(older)} recovered from leftover data in earlier versions of the history file's pages (kept in its " +
                      $"write-ahead log or replaced pages; marked \"{Label}\"). Such rows may have been deleted, or be an older copy of a visit the browser changed.");
        if (r.Spilled > 0)
            notes.Add($"{who}: {r.Spilled} leftover address {(r.Spilled == 1 ? "entry was" : "entries were")} too long to recover (the rest of the entry was on another page).");
    }

    // ---------------------------------------------------------------- pages of the database and its log

    /// <summary>
    /// Finds the database's current pages (main file, replaced by the last committed log frame of each page) and hands
    /// the engine: free space of current table pages, whole freelist pages, pages past the database's end, and every
    /// older page version (main-file pages the log replaces, log frames replaced later, uncommitted or stale frames).
    /// </summary>
    static void Walk(byte[]? main, byte[]? wal, Engine engine, CancellationToken ct)
    {
        main ??= [];
        bool mainOk = main.Length >= 100 && main.AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8);
        int pageSize = mainOk ? PageSizeOf(BE16(main, 16)) : 0;

        // Write-ahead log: valid frames are the prefix whose salts and running checksums match the log header. Frames
        // after the last commit that carry the header's salts are a change still being written (or torn): not older
        // data, so they are skipped. Frames with other salts are left from an earlier round of the log: older page versions.
        var frames = new List<(uint Page, int Data, bool Committed, bool Earlier)>();
        uint commitSize = 0;
        if (wal is { Length: >= 32 } && BE32(wal, 0) is 0x377f0682 or 0x377f0683)
        {
            int walPage = PageSizeOf(BE32(wal, 8) is var v and <= 65536 ? (int)v : 0);
            if (pageSize == 0) pageSize = walPage;
            if (walPage != 0 && walPage == pageSize)
            {
                bool big = (BE32(wal, 0) & 1) != 0;
                uint salt1 = BE32(wal, 16), salt2 = BE32(wal, 20);
                var (s0, s1) = Checksum(wal, 0, 24, big, 0, 0);
                bool valid = s0 == BE32(wal, 24) && s1 == BE32(wal, 28);
                int last = -1;
                for (long off = 32; off + 24 + pageSize <= wal.Length; off += 24 + pageSize)
                {
                    int o = (int)off;
                    if (valid)
                    {
                        valid = BE32(wal, o + 8) == salt1 && BE32(wal, o + 12) == salt2;
                        if (valid)
                        {
                            (s0, s1) = Checksum(wal, o, 8, big, s0, s1);
                            (s0, s1) = Checksum(wal, o + 24, pageSize, big, s0, s1);
                            valid = s0 == BE32(wal, o + 16) && s1 == BE32(wal, o + 20);
                        }
                    }
                    frames.Add((BE32(wal, o), o + 24, false, BE32(wal, o + 8) != salt1 || BE32(wal, o + 12) != salt2));
                    if (valid && BE32(wal, o + 4) is var size and > 0) { last = frames.Count - 1; commitSize = size; }
                }
                for (int i = 0; i <= last; i++) frames[i] = frames[i] with { Committed = true };
            }
        }
        if (pageSize == 0) pageSize = GuessPageSize(main);
        if (pageSize == 0) return;

        // Current version of each page.
        var current = new Dictionary<uint, int>();          // page -> index of its last committed frame
        for (int i = 0; i < frames.Count; i++) if (frames[i].Committed) current[frames[i].Page] = i;
        uint mainPages = (uint)(main.Length / pageSize);
        bool Current(uint page, out byte[] buf, out int off)
        {
            if (current.TryGetValue(page, out var i)) { buf = wal!; off = frames[i].Data; return true; }
            if (page >= 1 && page <= mainPages) { buf = main; off = (int)((page - 1) * (long)pageSize); return true; }
            buf = []; off = 0; return false;
        }

        if (!Current(1, out var p1, out var p1Off) || !p1.AsSpan(p1Off, 16).SequenceEqual("SQLite format 3\0"u8))
        {
            // No readable header: every page is searched as free space with UTF-8 text and no reserved bytes.
            engine.SetGeometry(pageSize, 0, 1);
            for (uint pg = 1; pg <= mainPages; pg++) { Tick(pg, ct); engine.Full(main, (int)((pg - 1) * (long)pageSize), FreeSpace); }
            foreach (var f in frames) if (f.Committed || f.Earlier) engine.Full(wal!, f.Data, OlderCopy);
            return;
        }
        if (!engine.SetGeometry(pageSize, p1[p1Off + 20], BE32(p1, p1Off + 56))) return;

        uint maxPage = Math.Max(mainPages, frames.Count == 0 ? 0 : frames.Max(f => f.Page));
        uint dbSize = commitSize != 0 ? commitSize : BE32(p1, p1Off + 28);
        if (dbSize == 0 || dbSize > maxPage) dbSize = maxPage;

        // Freelist: trunk pages (next trunk, leaf count, leaf numbers; the rest is old content) and their leaves.
        var free = new Dictionary<uint, int>();             // page -> where its old content starts
        uint trunk = BE32(p1, p1Off + 32);
        for (int steps = 0; trunk != 0 && trunk <= dbSize && steps <= dbSize && !free.ContainsKey(trunk); steps++)
        {
            if (!Current(trunk, out var tb, out var to)) break;
            uint next = BE32(tb, to), leaves = BE32(tb, to + 4);
            if (leaves > (uint)(engine.Usable / 4 - 2)) break;
            free[trunk] = 8 + 4 * (int)leaves;
            for (int i = 0; i < leaves; i++)
                if (BE32(tb, to + 8 + 4 * i) is var leaf and >= 1 && leaf <= dbSize) free.TryAdd(leaf, 0);
            trunk = next;
        }

        for (uint pg = 1; pg <= dbSize; pg++)
        {
            Tick(pg, ct);
            if (!Current(pg, out var b, out var o)) continue;
            if (free.TryGetValue(pg, out var start)) engine.Full(b, o, FreeSpace, start, start == 0 ? 0 : -1);
            else engine.Free(b, o, pg == 1 ? 100 : 0, FreeSpace);
        }
        for (uint pg = dbSize + 1; pg <= mainPages; pg++) { Tick(pg, ct); engine.Full(main, (int)((pg - 1) * (long)pageSize), FreeSpace); }
        foreach (var pg in current.Keys)
            if (pg <= mainPages) { Tick(pg, ct); engine.Full(main, (int)((pg - 1) * (long)pageSize), OlderCopy, pg == 1 ? 100 : 0, pg == 1 ? 100 : 0); }
        for (int i = 0; i < frames.Count; i++)
        {
            Tick((uint)i, ct);
            var f = frames[i];
            if (current.TryGetValue(f.Page, out var cur) && cur == i) continue;
            if (!f.Committed && !f.Earlier) continue;                      // an unsaved change, not an older version
            engine.Full(wal!, f.Data, OlderCopy, f.Page == 1 ? 100 : 0, f.Page == 1 ? 100 : 0);
        }
    }

    /// <summary>
    /// A file whose header is damaged and has no log: the header's page-size field if it still holds a valid value, else the
    /// largest page size (up to 64 KB) that divides the file. Too large is harmless (pages are searched offset by offset and
    /// rows never cross a real page boundary); too small would cut rows in two.
    /// </summary>
    static int GuessPageSize(byte[] main)
    {
        if (main.Length >= 100 && PageSizeOf(BE16(main, 16)) is var fromHeader and > 0 && main.Length % fromHeader == 0) return fromHeader;
        for (int size = 65536; size >= 512; size >>= 1)
            if (main.Length >= size && main.Length % size == 0) return size;
        return 0;
    }

    static void Tick(uint n, CancellationToken ct) { if ((n & 63) == 0) ct.ThrowIfCancellationRequested(); }

    static int PageSizeOf(int v) => v == 1 ? 65536 : v is >= 512 and <= 32768 && (v & (v - 1)) == 0 ? v : 0;

    static (uint, uint) Checksum(byte[] b, int off, int len, bool big, uint s0, uint s1)
    {
        unchecked
        {
            for (int i = off; i + 8 <= off + len; i += 8)
            {
                uint x0 = big ? BE32(b, i) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i));
                uint x1 = big ? BE32(b, i + 4) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i + 4));
                s0 += x0 + s1;
                s1 += x1 + s0;
            }
        }
        return (s0, s1);
    }

    static int BE16(byte[] b, int o) => BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o));
    static uint BE32(byte[] b, int o) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o));

    // ---------------------------------------------------------------- table layouts

    /// <summary>Column order of a freshly created table in current Chrome and Firefox, for files whose schema cannot be read.</summary>
    static readonly Dictionary<string, string[]> DefaultColumns = new(StringComparer.Ordinal)
    {
        ["urls"] = ["id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"],
        ["visits"] = ["id", "url", "visit_time", "from_visit", "external_referrer_url", "transition", "segment_id", "visit_duration",
            "incremented_omnibox_typed_score", "opener_visit", "originator_cache_guid", "originator_visit_id", "originator_from_visit",
            "originator_opener_visit", "is_known_to_sync", "consider_for_ntp_most_visited", "visited_link_id", "app_id"],
        ["moz_places"] = ["id", "url", "title", "rev_host", "visit_count", "hidden", "typed", "frecency", "last_visit_date", "guid",
            "foreign_count", "url_hash", "description", "preview_image_url", "site_name", "origin_id", "recalc_frecency", "alt_frecency",
            "recalc_alt_frecency"],
        ["moz_historyvisits"] = ["id", "from_visit", "place_id", "visit_date", "visit_type", "session", "source", "triggeringPlaceId"],
    };

    internal enum Role { Urls, Visits }
    internal enum Kind : byte { RowidNull, Int, IntOrNull, Text, TextOrNull, Any }

    /// <summary>A table's columns as the live database declares them, with what each column may hold.</summary>
    internal sealed class Layout
    {
        public required Role Role { get; init; }
        public required Kind[] Kinds { get; init; }
        /// <summary>Rows written before later columns were added have fewer columns; never fewer than this.</summary>
        public required int MinCols { get; init; }
        public int Url = -1, Title = -1, Time = -1, Hidden = -1, RevHost = -1, Ref = -1, KindCol = -1, Duration = -1;

        /// <param name="conn">The live database; null when it cannot be opened (damaged), then the browser's own current column order is used.</param>
        public static Layout? FromSchema(SqliteConnection? conn, string table, Role role, Dictionary<string, Kind> kinds,
            string? url = null, string? title = null, string? time = null, string? hidden = null, string? revHost = null,
            string? reference = null, string? kind = null, string? duration = null)
        {
            var names = new List<string>();
            if (conn is null) names.AddRange(DefaultColumns[table]);
            else
                try
                {
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = $"PRAGMA table_info({table})";      // constant table names only
                    using var r = cmd.ExecuteReader();
                    while (r.Read()) names.Add(r.GetString(1));
                }
                catch (SqliteException) { names.AddRange(DefaultColumns[table]); }
            if (names.Count == 0 || names.Count > 60 || names[0] != "id") return null;
            int At(string? n) => n is null ? -1 : names.IndexOf(n);
            var required = new[] { url, title, time, reference, kind }.Where(n => n is not null).Select(At).ToList();
            if (required.Any(i => i < 0)) return null;
            return new Layout
            {
                Role = role,
                Kinds = [.. names.Select(n => kinds.TryGetValue(n, out var k) ? k : SqliteCarver.Kind.Any)],
                MinCols = required.Max() + 1,
                Url = At(url), Title = At(title), Time = At(time), Hidden = At(hidden), RevHost = At(revHost),
                Ref = At(reference), KindCol = At(kind), Duration = At(duration),
            };
        }
    }

    // ---------------------------------------------------------------- record decoding

    /// <summary>One decoded candidate row. RowId is null when the cell's first bytes were overwritten.</summary>
    internal readonly record struct Row(Layout Layout, long? RowId, long Ref, string? Url, string? Title, long Time, long Kind, long Duration, bool Hidden, string Where);

    sealed class Engine(Layout[] layouts, Func<long, DateTimeOffset?> toTime, Func<long, bool> kindOk, DateTimeOffset now, LiveIndex live)
    {
        public readonly List<Row> Rows = [];
        /// <summary>Too-long deleted address rows, keyed by the start and length of their address.</summary>
        public readonly HashSet<string> SpilledKeys = [];
        readonly int _maxCols = layouts.Length == 0 ? 0 : layouts.Max(l => l.Kinds.Length);
        readonly long[] _types = new long[64];
        readonly int[] _offsets = new int[64];
        readonly DateTimeOffset _latest = now.AddDays(1);
        HashSet<string>? _liveKeys;
        int _pageSize;
        Encoding _text = Strict.Utf8;
        public int Usable { get; private set; }
        int _maxLocal, _minLocal;

        public bool SetGeometry(int pageSize, int reserved, uint encoding)
        {
            _pageSize = pageSize;
            Usable = pageSize - reserved;
            _maxLocal = Usable - 35;
            _minLocal = (Usable - 12) * 32 / 255 - 23;
            _text = encoding switch { 2 => Strict.Utf16Le, 3 => Strict.Utf16Be, _ => Strict.Utf8 };
            return Usable >= 480 && layouts.Length > 0;
        }

        /// <summary>A whole page whose content is no longer (or not necessarily) live: every offset is tried.</summary>
        /// <param name="header">Where the old b-tree page header is (to follow its freeblocks), or -1 when it was overwritten.</param>
        public void Full(byte[] buf, int off, string where, int start = 0, int header = 0)
        {
            if (Usable < 480 || off + _pageSize > buf.Length) return;
            var p = new ReadOnlySpan<byte>(buf, off, Usable);
            if (header >= 0 && header + 8 <= p.Length && p[header] is 0x02 or 0x05 or 0x0A or 0x0D)
                foreach (var (f, size) in Freeblocks(p, header)) Chain(p, f, f + size, where);
            Scan(p, start, p.Length, where);
        }

        /// <summary>
        /// A current b-tree page: only its free space (the gap before the cells and the freeblocks) is searched. Any page
        /// type counts: a page that once held rows and was reused as an index or interior page keeps them in its gap.
        /// </summary>
        public void Free(byte[] buf, int off, int header, string where)
        {
            if (Usable < 480 || off + _pageSize > buf.Length) return;
            var p = new ReadOnlySpan<byte>(buf, off, Usable);
            int type = p[header];
            if (type is not (0x02 or 0x05 or 0x0A or 0x0D)) return;     // overflow and pointer-map pages hold no free space
            int cells = (p[header + 3] << 8) | p[header + 4];
            int content = (p[header + 5] << 8) | p[header + 6];
            if (content == 0) content = 65536;
            int gapStart = header + (type is 0x02 or 0x05 ? 12 : 8) + 2 * cells, gapEnd = Math.Min(content, p.Length);
            if (gapStart < gapEnd) Scan(p, gapStart, gapEnd, where);
            foreach (var (f, size) in Freeblocks(p, header))
            {
                Chain(p, f, f + size, where);
                Scan(p, f + 4, f + size, where);
            }
        }

        static List<(int Offset, int Size)> Freeblocks(ReadOnlySpan<byte> p, int header)
        {
            var list = new List<(int, int)>();
            int f = (p[header + 1] << 8) | p[header + 2];
            while (f != 0 && list.Count < 4096)
            {
                if (f < header + 8 || f + 4 > p.Length) break;
                int next = (p[f] << 8) | p[f + 1], size = (p[f + 2] << 8) | p[f + 3];
                if (size < 4 || f + size > p.Length) break;
                list.Add((f, size));
                if (next != 0 && next <= f) break;                 // freeblocks are kept in ascending order
                f = next;
            }
            return list;
        }

        /// <summary>
        /// Tries a whole cell at every offset in [from, to); after a hit, follows the cells freed next to it. A cell must
        /// lie entirely inside the free region: one that runs into live cells has had its end overwritten.
        /// </summary>
        void Scan(ReadOnlySpan<byte> p, int from, int to, string where)
        {
            for (int o = from; o < to; o++)
                if (Cell(p, o, to, where, out var end)) o = Chain(p, end, to, where) - 1;
        }

        /// <summary>A cell with its header intact: payload length, rowid, then a record exactly that long.</summary>
        bool Cell(ReadOnlySpan<byte> p, int o, int limit, string where, out int end)
        {
            end = 0;
            if (!Varint(p, o, limit, out var payload, out var a) || payload < 3) return false;
            if (!Varint(p, o + a, limit, out var rowid, out var b) || rowid <= 0) return false;
            int q = o + a + b;
            // Every layout's record starts [header length][0 = the NULL id column]: a cheap test before any decoding.
            if (q + 2 >= limit || p[p[q] < 0x80 ? q + 1 : q + 2] != 0) return false;
            if (payload > _maxLocal) { SpillAt(p, q, payload, rowid, limit); return false; }
            if (q + payload > limit) return false;
            return Explicit(p, q, q + (int)payload, rowid, exact: true, where, out end);
        }

        /// <summary>
        /// Cells freed next to each other: each one's first 4 bytes were overwritten when it was freed (the freeblock's
        /// next offset and size), and a neighbour freed later merges into the same freeblock. So after each recovered
        /// cell, the next cell starts where it ended: tried with its header intact, then with its first bytes lost.
        /// </summary>
        int Chain(ReadOnlySpan<byte> p, int cell, int end, string where)
        {
            for (int guard = 0; guard < 4096 && cell + 5 < end; guard++)
            {
                if (Cell(p, cell, end, where, out var next) || LostHeader(p, cell, end, where, out next))
                {
                    if (next <= cell) break;
                    cell = next;
                }
                else break;
            }
            return cell;
        }

        /// <summary>
        /// A cell whose first 4 bytes (payload length, rowid and often the record's header length) were overwritten.
        /// Tried: the record header starting right after (with its length), or the column types alone (with or without
        /// the first, always-NULL id column). The rowid is then unknown.
        /// </summary>
        bool LostHeader(ReadOnlySpan<byte> p, int cell, int end, string where, out int recordEnd)
        {
            recordEnd = 0;
            for (int pos = cell + 4; pos <= cell + 5 && pos < end; pos++)
            {
                if (Explicit(p, pos, end, null, exact: false, where, out recordEnd)) return true;
                foreach (var layout in layouts)
                    for (int skip = 0; skip <= 1; skip++)
                    {
                        int n = layout.Kinds.Length, x = pos;
                        if (skip == 1) _types[0] = 0;
                        bool ok = true;
                        for (int i = skip; i < n && ok; i++)
                        {
                            ok = Varint(p, x, end, out _types[i], out var len);
                            x += len;
                        }
                        if (ok && Match(p, n, x, end, -1, null, where, layout, out recordEnd)) return true;
                    }
            }
            return false;
        }

        bool Explicit(ReadOnlySpan<byte> p, int pos, int end, long? rowid, bool exact, string where, out int recordEnd)
        {
            recordEnd = 0;
            if (!Header(p, pos, end, out var n, out var bodyStart)) return false;
            return Match(p, n, bodyStart, end, exact ? end : -1, rowid, where, null, out recordEnd);
        }

        /// <summary>Reads a record header (its length, then one serial type per column) that must end exactly where it says.</summary>
        bool Header(ReadOnlySpan<byte> p, int pos, int end, out int n, out int bodyStart)
        {
            n = 0; bodyStart = 0;
            if (!Varint(p, pos, end, out var h, out var hl) || h < 2 || h > 9 + 9 * _maxCols || pos + h > end) return false;
            int x = pos + hl, he = pos + (int)h;
            while (x < he)
            {
                if (n == _maxCols || !Varint(p, x, he, out _types[n], out var tl)) return false;
                n++; x += tl;
            }
            bodyStart = he;
            return x == he && n > 0;
        }

        /// <summary>Do the parsed serial types fit the layout? Fills the column offsets and the record's end.</summary>
        bool Fits(Layout l, int n, int bodyStart, out long recordEnd)
        {
            recordEnd = bodyStart;
            if (n < l.MinCols || n > l.Kinds.Length) return false;
            for (int i = 0; i < n; i++)
            {
                var t = _types[i];
                var size = Size(t);
                if (size < 0 || !SqliteCarver.Fits(l.Kinds[i], t)) return false;
                _offsets[i] = (int)Math.Min(recordEnd, int.MaxValue);
                recordEnd += size;
            }
            return true;
        }

        /// <summary>Matches the parsed serial types against the layouts, then decodes and checks the values.</summary>
        bool Match(ReadOnlySpan<byte> p, int n, int bodyStart, int end, int exactEnd, long? rowid, string where, Layout? only, out int recordEnd)
        {
            recordEnd = 0;
            if (n == 0 || _types[0] != 0) return false;           // every layout starts with the rowid alias, stored as NULL
            foreach (var l in layouts)
            {
                if ((only is not null && l != only) || !Fits(l, n, bodyStart, out var at)) continue;
                if (at > end)
                {
                    // A freed cell is never cut short by its freeblock unless the rest of it is on overflow pages.
                    if (exactEnd < 0 && l.Role == Role.Urls && at - bodyStart > _minLocal) Spilled(p, l, n, end, rowid);
                    continue;
                }
                if (exactEnd >= 0 && at != exactEnd) continue;
                if (Decode(p, l, n, rowid, where))
                {
                    recordEnd = (int)at;
                    return true;
                }
            }
            return false;
        }

        bool Decode(ReadOnlySpan<byte> p, Layout l, int n, long? rowid, string where)
        {
            long Int(ReadOnlySpan<byte> s, int i) => i < 0 || i >= n ? 0 : ReadInt(s, _types[i], _offsets[i]);
            bool Null(int i) => i < 0 || i >= n || _types[i] == 0;
            if (l.Role == Role.Urls)
            {
                if (!TryText(p, l.Url, n, out var url) || url is null || !PlausibleUrl(url)) return false;
                if (!TryText(p, l.Title, n, out var title) || (title is not null && HasControl(title))) return false;
                long time = Null(l.Time) ? 0 : Int(p, l.Time);
                if (time != 0 && !InWindow(time)) return false;
                if (l.RevHost >= 0 && !Null(l.RevHost))
                {
                    if (!TryText(p, l.RevHost, n, out var rev) || rev is null || !RevHostMatches(url, rev)) return false;
                }
                Rows.Add(new Row(l, rowid, 0, url, title, time, 0, 0, Int(p, l.Hidden) == 1, where));
                return true;
            }
            long reference = Int(p, l.Ref), when = Int(p, l.Time), kind = Int(p, l.KindCol), duration = Int(p, l.Duration);
            if (reference <= 0 || reference >= 1L << 40 || !InWindow(when) || !kindOk(kind) || duration < 0) return false;
            Rows.Add(new Row(l, rowid, reference, null, null, when, kind, duration, false, where));
            return true;
        }

        /// <summary>A whole cell whose payload is longer than a page can hold: only its first part is here.</summary>
        void SpillAt(ReadOnlySpan<byte> p, int q, long payload, long rowid, int limit)
        {
            long local = _minLocal + (payload - _minLocal) % (Usable - 4);
            if (local > _maxLocal) local = _minLocal;
            int localEnd = (int)Math.Min(q + local, limit);
            if (!Header(p, q, localEnd, out var n, out var body) || _types[0] != 0) return;
            foreach (var l in layouts)
                if (l.Role == Role.Urls && Fits(l, n, body, out _)) { Spilled(p, l, n, localEnd, rowid); return; }
        }

        /// <summary>Counts a too-long address row (never recovered) when its address starts like one and it is not a live row.</summary>
        void Spilled(ReadOnlySpan<byte> p, Layout l, int n, int limit, long? rowid)
        {
            if (l.Url >= n) return;
            long urlLen = Size(_types[l.Url]);
            int start = _offsets[l.Url], take = (int)Math.Min(urlLen, 48);
            if (start + take > limit || take < 10) return;
            var prefix = p.Slice(start, take);
            if (!(prefix.StartsWith("http"u8) || prefix.StartsWith("ftp:"u8) || prefix.StartsWith("file:"u8))) return;
            if (rowid is { } id && live.Urls.ContainsKey(id)) return;
            var key = Key(prefix, urlLen);
            _liveKeys ??= live.Urls.Values.Select(u => Encoding.UTF8.GetBytes(u.Url)).Select(b => Key(b.AsSpan(0, Math.Min(b.Length, 48)), b.Length)).ToHashSet();
            if (!_liveKeys.Contains(key)) SpilledKeys.Add(key);
        }

        static string Key(ReadOnlySpan<byte> prefix, long length) => Encoding.Latin1.GetString(prefix) + "|" + length;

        bool InWindow(long raw) => toTime(raw) is { } t && t >= Earliest && t <= _latest;

        bool TryText(ReadOnlySpan<byte> p, int i, int n, out string? s)
        {
            s = null;
            if (i < 0 || i >= n || _types[i] == 0) return true;
            var t = _types[i];
            if (t < 13 || (t & 1) == 0) return false;
            try { s = _text.GetString(p.Slice(_offsets[i], (int)Size(t))); return true; }
            catch (DecoderFallbackException) { return false; }
        }
    }

    static bool Fits(Kind k, long t) => k switch
    {
        Kind.RowidNull => t == 0,
        Kind.Int => t is >= 1 and <= 6 or 8 or 9,
        Kind.IntOrNull => t is >= 0 and <= 6 or 8 or 9,
        Kind.Text => t >= 13 && (t & 1) == 1,
        Kind.TextOrNull => t == 0 || (t >= 13 && (t & 1) == 1),
        _ => t is >= 0 and not 10 and not 11,
    };

    /// <summary>Bytes a serial type takes in the record body; -1 for reserved or absurd types.</summary>
    static long Size(long t) => t switch
    {
        0 or 8 or 9 => 0,
        >= 1 and <= 4 => t,
        5 => 6,
        6 or 7 => 8,
        10 or 11 => -1,
        >= 12 and < 1L << 20 => (t - 12) / 2,
        _ => -1,
    };

    static long ReadInt(ReadOnlySpan<byte> p, long t, int off)
    {
        int len = t switch { 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 6, 6 => 8, _ => 0 };
        if (t == 9) return 1;
        if (len == 0) return 0;
        long v = (sbyte)p[off];                                  // sign from the first byte
        for (int i = 1; i < len; i++) v = (v << 8) | p[off + i];
        return v;
    }

    /// <summary>SQLite varint: 1-9 bytes, big-endian, 7 bits per byte (8 in the ninth). False when it would run past <paramref name="end"/>.</summary>
    static bool Varint(ReadOnlySpan<byte> p, int pos, int end, out long value, out int length)
    {
        value = 0; length = 0;
        for (int i = 0; i < 9; i++)
        {
            if (pos + i >= end) return false;
            byte c = p[pos + i];
            if (i == 8) { value = (value << 8) | c; length = 9; return true; }
            value = (value << 7) | (long)(c & 0x7F);
            if (c < 0x80) { length = i + 1; return true; }
        }
        return false;
    }

    static bool PlausibleUrl(string url)
    {
        if (url.Length is < 10 or > 16384) return false;
        if (!(url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
              || url.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)))
            return false;
        foreach (var c in url) if (c <= ' ' || c == '\x7f' || c == '�') return false;
        return true;
    }

    static bool HasControl(string s)
    {
        foreach (var c in s) if ((c < ' ' && c != '\t') || c == '\x7f' || c == '�') return true;
        return false;
    }

    /// <summary>Firefox keeps the host reversed with a trailing dot ("moc.elpmaxe.www."); a mismatch means a bad decode.</summary>
    static bool RevHostMatches(string url, string rev)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Host.Length == 0) return rev == ".";
        var host = u.Host.ToLowerInvariant().ToCharArray();
        Array.Reverse(host);
        return string.Equals(rev, new string(host) + ".", StringComparison.OrdinalIgnoreCase);
    }

    static class Strict
    {
        public static readonly Encoding Utf8 = new UTF8Encoding(false, true);
        public static readonly Encoding Utf16Le = new UnicodeEncoding(false, false, true);
        public static readonly Encoding Utf16Be = new UnicodeEncoding(true, false, true);
    }

    // ---------------------------------------------------------------- live rows and the final list

    /// <summary>What the live database holds, so carved copies of live rows are dropped.</summary>
    sealed class LiveIndex
    {
        public readonly Dictionary<long, (string Url, string? Title)> Urls = [];
        public readonly HashSet<long> VisitIds = [];
        public readonly HashSet<(string Url, long Second)> VisitKeys = [];

        public static LiveIndex Read(SqliteConnection? conn, string urlSql, string visitSql)
        {
            var index = new LiveIndex();
            if (conn is null) return index;                      // a damaged file: nothing could be read live
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = urlSql;
                using (var r = cmd.ExecuteReader())
                    while (r.Read())
                        if (!r.IsDBNull(1)) index.Urls[r.GetInt64(0)] = (r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2));
                cmd.CommandText = visitSql;
                using (var r = cmd.ExecuteReader())
                    while (r.Read())
                    {
                        index.VisitIds.Add(r.GetInt64(0));
                        if (!r.IsDBNull(1) && !r.IsDBNull(2)) index.VisitKeys.Add((r.GetString(2), Second(r.GetInt64(1))));
                    }
            }
            catch (SqliteException) { }                          // a missing table: nothing live to compare with
            return index;
        }
    }

    static long Second(long micros) => micros / 1_000_000;

    /// <summary>
    /// Visits joined to their address (live by id, else a carved address row with that id; never when the two
    /// disagree), then address rows on their own (their last visit) when no visit already covers them. Anything
    /// whose id or (address, time to the second) is live is dropped, and each (address, second) appears once.
    /// </summary>
    static Result Assemble(BrowserProfile profile, Engine engine, LiveIndex live, Func<long, DateTimeOffset?> toTime,
        Func<long, VisitHow?> how, Func<long, long> seconds)
    {
        var urlRows = engine.Rows.Where(r => r.Layout.Role == Role.Urls).ToList();
        var byId = new Dictionary<long, Row>();
        foreach (var r in urlRows)
            if (r.RowId is { } id && (!byId.TryGetValue(id, out var seen) || (seen.Title is null && r.Title is not null))) byId[id] = r;

        // A freed cell loses its rowid, so a deleted address row usually has no id. Its last-visit time is the exact
        // microsecond of its newest visit, which ties the visits' address id to it (only when exactly one address has that time).
        var byTime = urlRows.Where(r => r.Time != 0).GroupBy(r => r.Time)
            .Where(g => g.Select(r => r.Url).Distinct().Count() == 1).ToDictionary(g => g.Key, g => g.OrderBy(r => r.Title is null).First());
        var visitRows = engine.Rows.Where(r => r.Layout.Role == Role.Visits).OrderBy(r => r.Time).ToList();
        var refs = new Dictionary<long, Row?>();             // address id -> carved address row (null: two different ones)
        foreach (var r in visitRows)
            if (!live.Urls.ContainsKey(r.Ref) && !byId.ContainsKey(r.Ref) && byTime.TryGetValue(r.Time, out var u))
                refs[r.Ref] = refs.TryGetValue(r.Ref, out var had) && had is { } h && h.Url != u.Url ? null : (had ?? u);

        // Copies of one visit (same id) from different places must agree; if they do not, none of them is trusted.
        var conflicting = visitRows.Where(r => r.RowId is not null).GroupBy(r => r.RowId!.Value)
            .Where(g => g.Select(r => (r.Ref, r.Time, r.Kind)).Distinct().Count() > 1).Select(g => g.Key).ToHashSet();

        var visits = new List<Visit>();
        var emitted = new HashSet<(string, long)>();
        var visitIds = new HashSet<long>();
        foreach (var r in visitRows)
        {
            if (r.RowId is { } vid && (live.VisitIds.Contains(vid) || conflicting.Contains(vid) || !visitIds.Add(vid))) continue;
            string url; string? title;
            Row? carvedUrl = null;
            if (live.Urls.TryGetValue(r.Ref, out var lu))
            {
                if (byId.TryGetValue(r.Ref, out var cu) && cu.Url != lu.Url) continue;    // the id was reused: which address is unknown
                (url, title) = lu;
            }
            else if (byId.TryGetValue(r.Ref, out var cu)) { (url, title) = (cu.Url!, cu.Title); carvedUrl = cu; }
            else if (refs.TryGetValue(r.Ref, out var tu) && tu is { } t) { (url, title) = (t.Url!, t.Title); carvedUrl = t; }
            else continue;
            // A deleted address row kept the time of its newest visit: none of its visits can be later.
            if (carvedUrl is { Time: > 0 } c && r.Time > c.Time + 1_000_000) continue;
            var key = (url, Second(r.Time));
            if (live.VisitKeys.Contains(key) || !emitted.Add(key)) continue;
            if (how(r.Kind) is not { } h || toTime(r.Time) is not { } when) continue;    // parts of pages are not shown, as for live rows
            visits.Add(Make(profile, url, title, when, h, seconds(r.Duration), r.Where));
        }
        foreach (var r in urlRows)
        {
            if (r.Time == 0 || r.Hidden || (r.RowId is { } id && live.Urls.ContainsKey(id))) continue;
            var key = (r.Url!, Second(r.Time));
            if (live.VisitKeys.Contains(key) || !emitted.Add(key) || toTime(r.Time) is not { } when) continue;
            visits.Add(Make(profile, r.Url!, r.Title, when, VisitHow.Other, 0, r.Where));
        }
        return new Result(visits.OrderBy(v => v.When).ThenBy(v => v.Url, StringComparer.Ordinal).ToList(), engine.SpilledKeys.Count);
    }

    static Visit Make(BrowserProfile profile, string url, string? title, DateTimeOffset when, VisitHow how, long seconds, string where) =>
        new(profile, Redactor.Redact(url), string.IsNullOrEmpty(title) ? null : Redactor.Redact(title), when, how, seconds, Origin.Carved, where);
}
