using System.Globalization;
using PCPorter.Core.Snapshots;

namespace PCPorter.Core.Tests.Snapshots;

/// <summary>The shadow-copy journal: what a later run may delete, and what it must leave alone.</summary>
public sealed class VssJournalTests : IDisposable
{
    const string Vol = @"\\?\Volume{11111111-2222-3333-4444-555555555555}\";
    static readonly DateTime T0 = new(2026, 11, 27, 10, 0, 0, DateTimeKind.Utc);
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-vssjournal").FullName;
    string JournalPath => Path.Combine(_dir, "shadow-copies.txt");
    public void Dispose() => Directory.Delete(_dir, true);

    sealed class FakeShadows : IShadowCopies
    {
        public readonly List<ShadowInfo> Copies = [];
        public readonly List<string> Deleted = [];
        public Func<string, (uint, string?)>? OnCreate;
        public (uint Code, string? Id) Create(string volumeRoot) => OnCreate!(volumeRoot);
        public IReadOnlyList<ShadowInfo> List() => Copies.ToList();
        public void Delete(string id) { Deleted.Add(id); Copies.RemoveAll(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase)); }
        public string? VolumeName(string volumeRoot) => Vol;

        public ShadowInfo Add(DateTime at, bool ours = true, string? id = null)
        {
            var s = new ShadowInfo(id ?? Guid.NewGuid().ToString("B"), @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" + (Copies.Count + 1), Vol,
                Wmi(at), at, ClientAccessible: true, NoWriters: ours);
            Copies.Add(s);
            return s;
        }
    }

    static string Wmi(DateTime t) => t.ToString("yyyyMMddHHmmss.ffffff", CultureInfo.InvariantCulture) + "+000";

    const int Dead = 4242, Alive = 7, Me = 99;
    VssSnapshotProvider Provider(FakeShadows shadows, int self = Me, bool requireAdmin = false) =>
        new(JournalPath, shadows, requireAdmin, (pid, _) => pid is Alive or Me, (self, 1), () => T0);

    static string Created(ShadowInfo s, int pid) => $"created\t{s.Id}\t{pid}\t1\t{s.VolumeName}\t{s.InstallDate}";
    static string Pending(int pid, DateTime at) => $"pending\t{Guid.NewGuid():N}\t{pid}\t1\tC:\\\t{at:O}";

    [Fact]
    public void Clean_up_deletes_only_matching_copies_of_ended_runs()
    {
        var shadows = new FakeShadows();
        var stale = shadows.Add(T0);
        var reused = shadows.Add(T0.AddHours(1));                // same ID recorded with another creation time
        var live = shadows.Add(T0);
        var restorePoint = shadows.Add(T0, ours: false);
        var legacy = shadows.Add(T0);
        File.WriteAllLines(JournalPath,
        [
            Created(stale, Dead),
            $"created\t{reused.Id}\t{Dead}\t1\t{Vol}\t{Wmi(T0)}",
            Created(live, Alive),
            Created(restorePoint, Dead),
            legacy.Id,                                           // old format: no proof it is ours, never deleted
            "garbage",
        ]);

        Assert.Equal(1, Provider(shadows).CleanUpStale());
        Assert.Equal([stale.Id], shadows.Deleted);
        Assert.Equal([Created(live, Alive)], File.ReadAllLines(JournalPath));   // only the live run's entry is kept
    }

    [Fact]
    public void Pending_line_of_a_crashed_run_removes_the_one_copy_it_made()
    {
        var shadows = new FakeShadows();
        var orphan = shadows.Add(T0.AddSeconds(3));
        var older = shadows.Add(T0.AddHours(-3));
        var restorePoint = shadows.Add(T0.AddSeconds(1), ours: false);
        File.WriteAllLines(JournalPath, [Pending(Dead, T0)]);

        Assert.Equal(1, Provider(shadows).CleanUpStale());
        Assert.Equal([orphan.Id], shadows.Deleted);
        Assert.Empty(File.ReadAllLines(JournalPath));
        Assert.Contains(older, shadows.Copies);
        Assert.Contains(restorePoint, shadows.Copies);
    }

    [Fact]
    public void Pending_line_is_not_guessed_when_unsure()
    {
        var shadows = new FakeShadows();
        shadows.Add(T0.AddSeconds(2));
        shadows.Add(T0.AddSeconds(4));                            // two candidates: delete neither
        File.WriteAllLines(JournalPath, [Pending(Dead, T0)]);
        Assert.Equal(0, Provider(shadows).CleanUpStale());
        Assert.Empty(shadows.Deleted);

        var busy = new FakeShadows();
        busy.Add(T0.AddSeconds(2));                               // could be the live run's copy
        File.WriteAllLines(JournalPath, [Pending(Dead, T0), Pending(Alive, T0.AddSeconds(1))]);
        Assert.Equal(0, Provider(busy).CleanUpStale());
        Assert.Empty(busy.Deleted);
        Assert.Equal(2, File.ReadAllLines(JournalPath).Length);  // kept for a later run
    }

    [Fact]
    public void A_gui_and_a_cli_run_never_delete_each_others_live_snapshot()
    {
        var shadows = new FakeShadows();
        shadows.OnCreate = _ => (0, shadows.Add(T0).Id);
        using var gui = Provider(shadows, self: Me).Create(@"C:\");
        var line = Assert.Single(File.ReadAllLines(JournalPath));
        Assert.StartsWith("created\t", line);
        Assert.Contains($"\t{Me}\t", line);

        Assert.Equal(0, Provider(shadows, self: Alive).CleanUpStale());   // the other run: GUI process is alive
        Assert.Empty(shadows.Deleted);

        gui.Dispose();
        Assert.Single(shadows.Deleted);
        Assert.Empty(File.ReadAllLines(JournalPath));
    }

    [Fact]
    public void A_crash_between_asking_windows_and_recording_is_cleaned_up_later()
    {
        var shadows = new FakeShadows();
        shadows.OnCreate = _ => throw new System.Runtime.InteropServices.COMException("provider died");
        // The pending line is written before Windows is asked; a run killed right after Windows made the copy leaves both.
        shadows.Add(T0.AddSeconds(1));
        File.WriteAllLines(JournalPath, [Pending(Dead, T0)]);
        Assert.Equal(1, Provider(shadows).CleanUpStale());
        Assert.Empty(shadows.Copies);

        // An exception inside this run removes its own pending line (the copy, if any, is cleaned when this run has ended).
        Assert.Throws<System.Runtime.InteropServices.COMException>(() => Provider(shadows).Create(@"C:\"));
        Assert.DoesNotContain(File.ReadAllLines(JournalPath), l => l.StartsWith("pending", StringComparison.Ordinal));
    }

    [Fact]
    public void Unreadable_id_is_resolved_by_volume_and_time()
    {
        var shadows = new FakeShadows();
        ShadowInfo? made = null;
        shadows.OnCreate = _ => { made = shadows.Add(T0.AddSeconds(1)); return (0, "not-a-guid"); };
        using (var snap = Provider(shadows).Create(@"C:\"))
        {
            Assert.Equal(made!.DeviceObject, snap.DeviceRoot);
            Assert.StartsWith($"created\t{made.Id}", Assert.Single(File.ReadAllLines(JournalPath)));
        }
        Assert.Equal([made.Id], shadows.Deleted);

        // Not certain (two candidates): the pending line stays so a later run removes it.
        var two = new FakeShadows();
        two.OnCreate = _ => { two.Add(T0); two.Add(T0.AddSeconds(1)); return (0, null); };
        Assert.Throws<InvalidOperationException>(() => Provider(two).Create(@"C:\"));
        Assert.StartsWith("pending\t", Assert.Single(File.ReadAllLines(JournalPath)));
        Assert.Empty(two.Deleted);
    }

    [Fact]
    public void An_untrusted_journal_is_ignored_and_replaced()
    {
        // Elevated rules: a journal not owned by Administrators/SYSTEM (here: by the test's own account) is not acted on.
        var shadows = new FakeShadows();
        var s = shadows.Add(T0);
        File.WriteAllLines(JournalPath, [Created(s, Dead)]);
        try { Assert.Equal(0, Provider(shadows, requireAdmin: true).CleanUpStale()); }
        catch (Exception e) when (e is UnauthorizedAccessException or InvalidOperationException or IOException) { }   // cannot make an admin-owned file unelevated
        Assert.Empty(shadows.Deleted);
        if (File.Exists(JournalPath)) Assert.Empty(File.ReadAllLines(JournalPath));
    }
}
