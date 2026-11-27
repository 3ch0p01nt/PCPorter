using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class DateCorroboratorTests
{
    static readonly DateTimeOffset Jan = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Nov = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

    static GalleryItem Thumb(string user, string id, string? path = null) => new(
        $"t-{user}-{id}", "thumbnail", "File Explorer thumbnails", EvidenceLevel.Displayed, user, id, path, null,
        OriginalStatus.Unknown, false, null, [], new DateWindow(Jan, Nov, "Low", ["cache file times"]), null);

    [Fact]
    public void Restore_point_copy_tightens_the_window_and_raises_confidence()
    {
        var items = DateCorroborator.Apply([Thumb("bob", "aa"), Thumb("bob (restore point 2026-03-10)", "aa"), Thumb("bob (restore point 2026-05-01)", "aa")]);
        var live = items[0];
        Assert.Equal(new DateTimeOffset(2026, 3, 11, 0, 0, 0, TimeSpan.Zero), live.Dates!.Before);
        Assert.Equal("High", live.Dates.Confidence);
        Assert.Contains(live.Dates.Sources, s => s.Contains("restore point from 2026-03-10"));
    }

    [Fact]
    public void Other_users_and_ids_are_not_affected()
    {
        var items = DateCorroborator.Apply([Thumb("bob", "aa"), Thumb("alice (restore point 2026-03-10)", "aa"), Thumb("bob (restore point 2026-03-10)", "bb")]);
        Assert.Equal(Nov, items[0].Dates!.Before);
        Assert.Equal("Low", items[0].Dates!.Confidence);
    }

    [Fact]
    public void Opening_the_same_file_adds_a_supporting_line_only()
    {
        var opened = new GalleryItem("o-1", "opened", "Recent files", EvidenceLevel.Opened, "bob", null, @"C:\Pics\cat.jpg", null,
            OriginalStatus.Exists, false, null, [], new DateWindow(null, Nov.AddDays(-3), "Medium", ["opened"]), null);
        var items = DateCorroborator.Apply([Thumb("bob", "aa", @"c:\pics\CAT.jpg"), opened]);
        Assert.Equal(Nov, items[0].Dates!.Before);                       // window unchanged
        Assert.Contains(items[0].Dates!.Sources, s => s.StartsWith("Same file opened in an app"));
    }
}
