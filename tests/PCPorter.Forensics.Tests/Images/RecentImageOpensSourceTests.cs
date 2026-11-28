using PCPorter.Forensics.Images;
using Xunit.Abstractions;

namespace PCPorter.Forensics.Tests.Images;

/// <summary>Runs only when this PC's user has a Recent folder. Reads it read-only; prints counts only.</summary>
public sealed class LocalRecentFactAttribute : FactAttribute
{
    public static string Profile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public LocalRecentFactAttribute()
    {
        if (!Directory.Exists(Path.Combine(Profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent")))
            Skip = "No Recent folder on this PC.";
    }
}

public class RecentImageOpensSourceTests(ITestOutputHelper output)
{
    private static readonly byte[] TinyPng = ImageTestData.Png(8, 6, (x, y) => (x + y) / 14.0);

    [Fact]
    public void Shortcut_to_an_existing_picture_loads_it_with_shortcut_times()
    {
        using var profile = new TempProfile();
        var target = profile.Write(@"Pictures\holiday.png", TinyPng);
        var targetCreated = new DateTime(2025, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        var lnk = profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\holiday.png.lnk",
            ImageTestData.Lnk(target, targetCreated, targetCreated.AddDays(1), targetCreated.AddDays(2)));
        var first = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var last = new DateTime(2026, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        File.SetCreationTimeUtc(lnk, first);
        File.SetLastWriteTimeUtc(lnk, last);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        var e = Assert.Single(new RecentImageOpensSource().Collect(ctx));

        Assert.Empty(ctx.Warnings);
        Assert.Equal(EvidenceLevel.Opened, e.Evidence);
        Assert.Equal(RecentImageOpensSource.ShortcutSource, e.Source);
        Assert.Equal(target, e.OriginalPath);
        Assert.Equal(first, e.FirstSeenUtc!.Value.UtcDateTime);
        Assert.Equal(last, e.LastSeenUtc!.Value.UtcDateTime);
        Assert.Equal(RecentImageOpensSource.ShortcutTimeMeaning, e.TimeMeaning);
        Assert.Equal(TinyPng, e.ImageBytes);
        Assert.Equal("image/png", e.ContentType);
        Assert.Contains("created 2025-06-01 12:00:00", e.Note);
        Assert.Contains("accessed 2025-06-03 12:00:00", e.Note);
        Assert.DoesNotContain(RecentImageOpensSource.MissingNote, e.Note);
    }

    [Fact]
    public void Shortcut_to_a_deleted_picture_says_so_and_non_pictures_are_ignored()
    {
        using var profile = new TempProfile();
        var t = DateTime.UtcNow;
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\gone.jpg.lnk",
            ImageTestData.Lnk(Path.Combine(profile.Folder, "Pictures", "gone.jpg"), t, t, t));
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\clip.mp4.lnk",
            ImageTestData.Lnk(Path.Combine(profile.Folder, "Videos", "clip.mp4"), t, t, t));
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\notes.txt.lnk",
            ImageTestData.Lnk(Path.Combine(profile.Folder, "notes.txt"), t, t, t));
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\broken.lnk", [1, 2, 3, 4, 5]);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        var items = new RecentImageOpensSource().Collect(ctx).ToList();

        Assert.Equal(2, items.Count);
        Assert.All(items, e =>
        {
            Assert.Null(e.ImageBytes);
            Assert.StartsWith(RecentImageOpensSource.MissingNote, e.Note);
        });
        Assert.Contains(items, e => e.ContentType == "video/mp4");
        Assert.Single(ctx.Warnings); // the broken shortcut
    }

    [Fact]
    public void Corrupt_jump_list_is_a_warning_not_an_exception()
    {
        using var profile = new TempProfile();
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms",
            new byte[600]);

        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        Assert.Empty(new RecentImageOpensSource().Collect(ctx));
        Assert.Single(ctx.Warnings);
    }

    [Fact]
    public void Jump_list_entries_map_to_opened_evidence()
    {
        using var profile = new TempProfile();
        var existing = profile.Write(@"Pictures\cat.png", TinyPng);
        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        var opened = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero);

        var e = RecentImageOpensSource.MapJumpListItem(ctx, "Photos",
            new RecentImageOpensSource.JumpListItem(existing, opened, 3, Pinned: true))!;
        Assert.Equal("Jump List (Photos)", e.Source);
        Assert.Equal(EvidenceLevel.Opened, e.Evidence);
        Assert.Null(e.FirstSeenUtc);
        Assert.Equal(opened, e.LastSeenUtc);
        Assert.Equal(RecentImageOpensSource.JumpListTimeMeaning, e.TimeMeaning);
        Assert.Equal(TinyPng, e.ImageBytes);
        Assert.Contains("opened 3 times", e.Note);
        Assert.Contains("pinned", e.Note);

        var gone = RecentImageOpensSource.MapJumpListItem(ctx, "Paint",
            new RecentImageOpensSource.JumpListItem(Path.Combine(profile.Folder, "x.HEIC"), opened, 0, false))!;
        Assert.Null(gone.ImageBytes);
        Assert.Equal(RecentImageOpensSource.MissingNote, gone.Note);

        var unrecorded = RecentImageOpensSource.MapJumpListItem(ctx, "Paint",
            new RecentImageOpensSource.JumpListItem(Path.Combine(profile.Folder, "y.jpg"), DateTimeOffset.FromFileTime(0), 0, false))!;
        Assert.Null(unrecorded.LastSeenUtc);

        Assert.Null(RecentImageOpensSource.MapJumpListItem(ctx, "Word",
            new RecentImageOpensSource.JumpListItem(Path.Combine(profile.Folder, "a.docx"), opened, 1, false)));
        Assert.Null(RecentImageOpensSource.MapJumpListItem(ctx, "Word",
            new RecentImageOpensSource.JumpListItem(null, opened, 1, false)));
    }

    [Fact]
    public void Cloud_only_targets_are_not_read()
    {
        using var profile = new TempProfile();
        var online = profile.Write(@"OneDrive\Pictures\cat.png", TinyPng);
        File.SetAttributes(online, File.GetAttributes(online) | FileAttributes.Offline);
        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());

        var e = RecentImageOpensSource.MapJumpListItem(ctx, "Photos", new RecentImageOpensSource.JumpListItem(online, null, 1, false))!;
        Assert.Null(e.ImageBytes);
        Assert.Contains(RecentImageOpensSource.CloudOnlyNote, e.Note);
    }

    [Fact]
    public void Targets_are_mapped_onto_the_scanned_drive_and_network_paths_are_not_touched()
    {
        Assert.Equal(@"E:\Users\bob\Pictures\a.jpg",
            RecentImageOpensSource.MapToSource(@"C:\Users\bob\Pictures\a.jpg", @"E:\Users\bob"));
        Assert.Null(RecentImageOpensSource.MapToSource(@"C:\Photos\a.jpg", @"E:\Users\bob"));
        Assert.Null(RecentImageOpensSource.MapToSource(@"\\server\share\a.jpg", @"C:\Users\bob"));
        Assert.Null(RecentImageOpensSource.MapToSource("knownfolder:{33E28130-4E1E-4676-835A-98395C3BC3BB}\\a.jpg", @"C:\Users\bob"));
        Assert.Equal(@"C:\Users\bob\a.jpg", RecentImageOpensSource.MapToSource(@"C:\Users\bob\a.jpg", @"C:\Users\bob"));
    }

    // Shortcuts and Jump Lists come from the old drive: they must be read through SourceFiles (inside the drive, no
    // links, size cap), never opened by the parsing libraries themselves.
    [Fact]
    public void Shortcuts_and_jump_lists_are_read_through_source_files()
    {
        using var profile = new TempProfile();
        var t = DateTime.UtcNow;
        var lnk = profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\a.png.lnk", ImageTestData.Lnk(Path.Combine(profile.Folder, "a.png"), t, t, t));
        var jump = profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms", [1, 2, 3]);
        var reads = new List<string>();
        using (PCPorter.Collectors.Sources.SourceFiles.Observe((kind, path) => { if (kind == "read") lock (reads) reads.Add(path); }))
            _ = new RecentImageOpensSource().Collect(new ImageSourceContext("bob", profile.Folder, new List<string>())).ToList();
        Assert.Contains(lnk, reads);
        Assert.Contains(jump, reads);
    }

    [Fact]
    public void An_oversized_shortcut_is_not_parsed()
    {
        using var profile = new TempProfile();
        var t = DateTime.UtcNow;
        var lnk = ImageTestData.Lnk(Path.Combine(profile.Folder, "a.png"), t, t, t);
        var big = new byte[RecentImageOpensSource.MaxListBytes + 1];
        lnk.CopyTo(big, 0);
        profile.Write(@"AppData\Roaming\Microsoft\Windows\Recent\a.png.lnk", big);
        var ctx = new ImageSourceContext("bob", profile.Folder, new List<string>());
        Assert.Empty(new RecentImageOpensSource().Collect(ctx));
        Assert.Contains(ctx.Warnings, w => w.Contains("a.png.lnk"));
    }

    [LocalRecentFact]
    [Trait("Category", "Live")]
    public void This_pcs_recent_files_and_jump_lists_parse_without_exceptions()
    {
        var ctx = new ImageSourceContext("me", LocalRecentFactAttribute.Profile, new List<string>());
        var items = new RecentImageOpensSource().Collect(ctx).ToList();

        int shortcuts = items.Count(e => e.Source == RecentImageOpensSource.ShortcutSource);
        output.WriteLine($"shortcut opens: {shortcuts}");
        output.WriteLine($"jump list opens: {items.Count - shortcuts}");
        output.WriteLine($"still present and loaded: {items.Count(e => e.ImageBytes is not null)}");
        output.WriteLine($"no longer exist: {items.Count(e => e.Note?.StartsWith(RecentImageOpensSource.MissingNote) == true)}");
        output.WriteLine($"warnings: {ctx.Warnings.Count}");
        Assert.All(items, e => Assert.Equal(EvidenceLevel.Opened, e.Evidence));
    }
}
