using System.Diagnostics;
using Microsoft.Data.Sqlite;
using PCPorter.Forensics.BrowserHistory;
using PCPorter.TestKit;
using static PCPorter.TestKit.ChromiumFixture;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class SqliteCarverTests
{
    static readonly DateTimeOffset T0 = new(2025, 6, 1, 8, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Now = new(2026, 11, 27, 12, 0, 0, TimeSpan.Zero);

    static BrowserProfile Chrome(string folder) => new("bob", "Google Chrome", BrowserFamily.Chromium, "Default", folder);
    static BrowserProfile Fox(string folder) => new("bob", "Firefox", BrowserFamily.Firefox, "default-release", folder);

    static string Address(int i) => $"https://site{i}.example/page/{i}?ref=carver";
    static string Title(int i, int pad = 0) => $"Title {i}" + new string('t', pad);
    static bool TwoInFive(int i) => i % 5 < 2;                  // 20 of 50, in pairs of neighbouring rows

    /// <summary>One address per row, each with one typed visit at T0 + i minutes; then the chosen rows are deleted the way Chrome does it.</summary>
    static void FillChrome(ChromiumFixture f, int count, Func<int, bool> deleted, int titlePad = 0)
    {
        f.Sql("BEGIN");
        for (int i = 0; i < count; i++)
        {
            var id = f.Url(Address(i), Title(i, titlePad), T0.AddMinutes(i));
            f.Visit(id, T0.AddMinutes(i), ChainStart | ChainEnd | 1, durationMicros: 2_000_000);
        }
        f.Sql("COMMIT");
        var ids = string.Join(",", Enumerable.Range(0, count).Where(deleted).Select(i => i + 1));
        f.Sql($"DELETE FROM visits WHERE url IN ({ids})");
        f.Sql($"DELETE FROM urls WHERE id IN ({ids})");
    }

    static HashSet<(string Url, string? Title, DateTimeOffset When)> Expected(int count, Func<int, bool> deleted, int titlePad = 0) =>
        Enumerable.Range(0, count).Where(deleted).Select(i => (Address(i), (string?)Title(i, titlePad), T0.AddMinutes(i))).ToHashSet();

    static HashSet<(string Url, string? Title, DateTimeOffset When)> Carved(IEnumerable<Visit> visits) =>
        visits.Where(v => v.Origin == Origin.Carved).Select(v => (v.Url, v.Title, v.When)).ToHashSet();

    /// <summary>Sorted text lines: xUnit compares these quickly and prints readable differences.</summary>
    static List<string> Text(IEnumerable<(string Url, string? Title, DateTimeOffset When)> rows) =>
        rows.Select(r => $"{r.When:O} {r.Url} {r.Title}").Order(StringComparer.Ordinal).ToList();

    static void AssertNoLiveRepeated(IReadOnlyList<Visit> visits)
    {
        var live = visits.Where(v => v.Origin == Origin.Live).Select(v => (v.Url, v.When)).ToHashSet();
        Assert.DoesNotContain(visits.Where(v => v.Origin == Origin.Carved), v => live.Contains((v.Url, v.When)));
        // Every fixture address has exactly one visit, so a second carved row for an address would be a false one.
        var carved = visits.Where(v => v.Origin == Origin.Carved).Select(v => v.Url).ToList();
        Assert.Equal(carved.Count, carved.Distinct().Count());
    }

    [Fact]
    public void Chrome_deleted_rows_come_back_with_their_times_and_live_rows_are_not_repeated()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder)) FillChrome(f, 50, TwoInFive);

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Equal(30, h.Visits.Count(v => v.Origin == Origin.Live));
            Assert.Equal(Text(Expected(50, TwoInFive)), Text(Carved(h.Visits)));
            Assert.All(h.Visits.Where(v => v.Origin == Origin.Carved), v =>
            {
                Assert.Equal(VisitHow.Typed, v.How);
                Assert.Equal(2, v.DurationSeconds);
                Assert.False(string.IsNullOrEmpty(v.OriginNote));
            });
            AssertNoLiveRepeated(h.Visits);
            Assert.Contains(h.Notes, n => n.Contains("20 deleted visits"));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Firefox_deleted_rows_come_back_with_their_times()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "abcd.default-release");
            using (var f = new FirefoxFixture(folder, "PRAGMA secure_delete=OFF; PRAGMA page_size=32768;"))     // Firefox's own page size
            {
                for (int i = 0; i < 50; i++)
                {
                    var place = f.Place(Address(i), Title(i));
                    f.Sql($"UPDATE moz_places SET last_visit_date = {FirefoxFixture.PrTime(T0.AddMinutes(i))}, rev_host = 'elpmaxe.{new string($"site{i}".Reverse().ToArray())}.' WHERE id = {place}");
                    f.Visit(place, T0.AddMinutes(i), 2);
                }
                var ids = string.Join(",", Enumerable.Range(0, 50).Where(TwoInFive).Select(i => i + 1));
                f.Sql($"DELETE FROM moz_historyvisits WHERE place_id IN ({ids})");
                f.Sql($"DELETE FROM moz_places WHERE id IN ({ids})");
            }

            var h = FirefoxHistoryReader.Read(Fox(folder), Path.Combine(dir, "work"));

            Assert.Equal(30, h.Visits.Count(v => v.Origin == Origin.Live));
            Assert.Equal(Text(Expected(50, TwoInFive)), Text(Carved(h.Visits)));
            Assert.All(h.Visits.Where(v => v.Origin == Origin.Carved), v => Assert.Equal(VisitHow.Typed, v.How));
            AssertNoLiveRepeated(h.Visits);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Theory]
    [InlineData(false)]     // everything (even the schema) is still only in the write-ahead log
    [InlineData(true)]      // the rows were saved to the main file; only the delete is in the log
    public void Deletes_still_in_the_write_ahead_log_are_recovered(bool checkpointFirst)
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using var f = new ChromiumFixture(folder, "PRAGMA secure_delete=OFF; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
            for (int i = 0; i < 50; i++)
            {
                var id = f.Url(Address(i), Title(i), T0.AddMinutes(i));
                f.Visit(id, T0.AddMinutes(i), ChainStart | ChainEnd | 1);
            }
            if (checkpointFirst) f.Sql("PRAGMA wal_checkpoint(TRUNCATE);");
            var ids = string.Join(",", Enumerable.Range(0, 50).Where(TwoInFive).Select(i => i + 1));
            f.Sql($"DELETE FROM visits WHERE url IN ({ids}); DELETE FROM urls WHERE id IN ({ids});");
            Assert.True(new FileInfo(f.Path + "-wal").Length > 0);

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));     // the writer still holds the database

            Assert.Equal(30, h.Visits.Count(v => v.Origin == Origin.Live));
            Assert.Equal(Text(Expected(50, TwoInFive)), Text(Carved(h.Visits)));
            AssertNoLiveRepeated(h.Visits);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Page_size_65536_is_read_from_the_header_value_1()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder, "PRAGMA secure_delete=OFF; PRAGMA page_size=65536;")) FillChrome(f, 50, TwoInFive);
            var header = File.ReadAllBytes(Path.Combine(folder, "History")).AsSpan(16, 2).ToArray();
            Assert.Equal(new byte[] { 0, 1 }, header);

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Equal(Text(Expected(50, TwoInFive)), Text(Carved(h.Visits)));
            AssertNoLiveRepeated(h.Visits);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Rows_on_pages_returned_to_the_freelist_are_recovered()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            static bool Middle(int i) => i is >= 100 and < 400;
            using (var f = new ChromiumFixture(folder)) FillChrome(f, 600, Middle, titlePad: 150);
            using (var c = new SqliteConnection($"Data Source={Path.Combine(folder, "History")};Pooling=False;Mode=ReadOnly"))
            {
                c.Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "PRAGMA freelist_count";
                Assert.True((long)cmd.ExecuteScalar()! > 5, "the fixture should leave whole pages on the freelist");
            }

            // Deleting this many rows makes SQLite merge and rewrite pages, which overwrites some deleted rows for good.
            // Every deleted address row whose values (address, title, last visit time) are all still in the file must
            // come back, and nothing else.
            var bytes = File.ReadAllBytes(Path.Combine(folder, "History"));
            var stillThere = Expected(600, Middle, 150).Where(e => WholeRowInFile(bytes, e)).ToHashSet();
            Assert.True(stillThere.Count > 150, $"only {stillThere.Count} deleted rows left in the file");

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Equal(300, h.Visits.Count(v => v.Origin == Origin.Live));
            Assert.Equal(Text(stillThere), Text(Carved(h.Visits)));
            AssertNoLiveRepeated(h.Visits);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    /// <summary>The body of a urls row as Chrome stores it: address, title, then last_visit_time as an 8-byte integer.</summary>
    static bool WholeRowInFile(byte[] file, (string Url, string? Title, DateTimeOffset When) row)
    {
        var time = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(time, BrowserFixtures.WebKit(row.When));
        byte[] body = [.. System.Text.Encoding.UTF8.GetBytes(row.Url), .. System.Text.Encoding.UTF8.GetBytes(row.Title ?? ""), .. time];
        return file.AsSpan().IndexOf(body) >= 0;
    }

    [Fact]
    public void Secure_delete_on_leaves_nothing_to_recover()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder, "PRAGMA secure_delete=ON;")) FillChrome(f, 50, TwoInFive);

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Equal(30, h.Visits.Count);
            Assert.DoesNotContain(h.Visits, v => v.Origin != Origin.Live);
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Rows_that_continued_on_overflow_pages_are_skipped_and_counted()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder))
            {
                for (int i = 0; i < 6; i++)
                {
                    var id = f.Url(Address(i), i == 2 ? Title(i, 6000) : Title(i), T0.AddMinutes(i));     // row 3 is larger than a page
                    f.Visit(id, T0.AddMinutes(i), ChainStart | ChainEnd | 1);
                }
                f.Sql("DELETE FROM visits WHERE url IN (3, 4); DELETE FROM urls WHERE id IN (3, 4);");
            }

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Equal(Text(Expected(6, i => i == 3)), Text(Carved(h.Visits)));
            Assert.Contains(h.Notes, n => n.Contains("1 deleted entry was too long"));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    /// <summary>A clean History file (nothing deleted) as raw bytes, plus an open connection for its schema and live rows.</summary>
    static (byte[] Main, SqliteConnection Live) CleanChrome(string dir)
    {
        var folder = Path.Combine(dir, "Default");
        using (var f = new ChromiumFixture(folder)) FillChrome(f, 20, _ => false);
        var path = Path.Combine(folder, "History");
        var conn = new SqliteConnection($"Data Source={path};Pooling=False;Mode=ReadOnly");
        conn.Open();
        return (File.ReadAllBytes(path), conn);
    }

    static byte[] RandomBytes(int length, int seed)
    {
        var b = new byte[length];
        new Random(seed).NextBytes(b);
        return b;
    }

    [Fact]
    public void Random_bytes_give_no_results()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var (main, live) = CleanChrome(dir);
            using (live)
            {
                var profile = Chrome(dir);
                // Random pages after the database's end are searched like free space.
                byte[] padded = [.. main, .. RandomBytes(64 * 4096, 1)];
                Assert.Empty(SqliteCarver.Chromium(profile, padded, null, live, Now).Visits);
                // The database header followed by random pages.
                byte[] header = [.. main.AsSpan(0, 4096), .. RandomBytes(64 * 4096, 2)];
                Assert.Empty(SqliteCarver.Chromium(profile, header, null, live, Now).Visits);
                // No header at all, and a random write-ahead log with a valid-looking header.
                byte[] wal = [0x37, 0x7f, 0x06, 0x82, 0, 0x2d, 0xe2, 0x18, 0, 0, 0x10, 0, .. RandomBytes(20 + 10 * (24 + 4096), 3)];
                Assert.Empty(SqliteCarver.Chromium(profile, RandomBytes(32 * 4096, 4), wal, live, Now).Visits);
                Assert.Empty(SqliteCarver.Chromium(profile, null, null, live, Now).Visits);
            }
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Truncated_and_garbled_files_never_throw_or_hang()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder, "PRAGMA secure_delete=OFF; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"))
            {
                FillChrome(f, 300, TwoInFive);
                File.Copy(f.Path, Path.Combine(dir, "main.bin"));
                using var src = new FileStream(f.Path + "-wal", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var dst = File.Create(Path.Combine(dir, "wal.bin"));
                src.CopyTo(dst);
            }
            var main = File.ReadAllBytes(Path.Combine(dir, "main.bin"));
            var wal = File.ReadAllBytes(Path.Combine(dir, "wal.bin"));
            using var live = new SqliteConnection($"Data Source={Path.Combine(folder, "History")};Pooling=False;Mode=ReadOnly");
            live.Open();

            var rnd = new Random(7);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var watch = Stopwatch.StartNew();
            for (int round = 0; round < 200; round++)
            {
                byte[]? m = Mutate(main, rnd), w = round % 3 == 0 ? null : Mutate(wal, rnd);
                var r = SqliteCarver.Chromium(Chrome(folder), m, w, live, Now, cts.Token);
                Assert.NotNull(r);
            }
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(60));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    /// <summary>Cuts, flips bytes in, or overwrites header fields of a copy of the file.</summary>
    static byte[] Mutate(byte[] source, Random rnd)
    {
        var b = source.AsSpan(0, rnd.Next(0, source.Length + 1)).ToArray();
        int kind = rnd.Next(4);
        if (b.Length == 0) return b;
        if (kind >= 1) for (int i = 0; i < 1 + rnd.Next(500); i++) b[rnd.Next(b.Length)] = (byte)rnd.Next(256);
        if (kind >= 2) for (int i = 0; i < Math.Min(100, b.Length); i++) if (rnd.Next(4) == 0) b[i] = (byte)rnd.Next(256);
        if (kind == 3 && b.Length > 64) rnd.NextBytes(b.AsSpan(rnd.Next(b.Length / 2), Math.Min(4096, b.Length / 2)));
        return b;
    }

    [Fact]
    public void A_50_MB_file_of_free_space_is_searched_in_a_few_seconds()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var (main, live) = CleanChrome(dir);
            using (live)
            {
                byte[] big = [.. main, .. RandomBytes(50 << 20, 9)];     // worst case: every byte is free space
                var watch = Stopwatch.StartNew();
                var r = SqliteCarver.Chromium(Chrome(dir), big, null, live, Now);
                watch.Stop();
                Assert.Empty(r.Visits);
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8), $"took {watch.Elapsed.TotalSeconds:F1} s");
            }
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    /// <summary>Wipes the 100-byte database header (magic, page size, everything) after the rows were written.</summary>
    static void BreakHeader(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Write);
        fs.Write(new byte[100]);
    }

    [Fact]
    public void Chrome_history_with_a_damaged_header_is_carved_with_a_warning()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "Default");
            using (var f = new ChromiumFixture(folder)) FillChrome(f, 30, _ => false);
            BreakHeader(Path.Combine(folder, "History"));

            var h = ChromiumHistoryReader.Read(Chrome(folder), Path.Combine(dir, "work"));

            Assert.Contains(h.Warnings, w => w.Contains("damaged") && w.Contains("carved", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(h.Visits, v => v.Origin != Origin.Carved);
            Assert.Equal(Text(Expected(30, _ => true)), Text(Carved(h.Visits)));
            Assert.All(h.Visits, v => Assert.Equal(VisitHow.Typed, v.How));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Firefox_history_with_a_damaged_header_is_carved_with_a_warning()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var folder = Path.Combine(dir, "abcd.default-release");
            using (var f = new FirefoxFixture(folder, "PRAGMA secure_delete=OFF; PRAGMA page_size=32768;"))
                for (int i = 0; i < 30; i++)
                {
                    var place = f.Place(Address(i), Title(i));
                    f.Sql($"UPDATE moz_places SET last_visit_date = {FirefoxFixture.PrTime(T0.AddMinutes(i))} WHERE id = {place}");
                    f.Visit(place, T0.AddMinutes(i), 2);
                }
            BreakHeader(Path.Combine(folder, "places.sqlite"));

            var h = FirefoxHistoryReader.Read(Fox(folder), Path.Combine(dir, "work"));

            Assert.Contains(h.Warnings, w => w.Contains("damaged") && w.Contains("carved", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(h.Visits, v => v.Origin != Origin.Carved);
            Assert.Equal(Text(Expected(30, _ => true)), Text(Carved(h.Visits)));
        }
        finally { BrowserFixtures.Delete(dir); }
    }

    [Fact]
    public void Cancellation_is_honoured()
    {
        var dir = BrowserFixtures.TempDir();
        try
        {
            var (main, live) = CleanChrome(dir);
            using (live)
            {
                byte[] big = [.. main, .. RandomBytes(8 << 20, 10)];
                using var cts = new CancellationTokenSource();
                cts.Cancel();
                Assert.ThrowsAny<OperationCanceledException>(() => SqliteCarver.Chromium(Chrome(dir), big, null, live, Now, cts.Token));
            }
        }
        finally { BrowserFixtures.Delete(dir); }
    }
}
