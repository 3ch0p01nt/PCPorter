using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class DateCorroboratorTests
{
    static readonly DateTimeOffset Jan = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Nov = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

    static GalleryItem Thumb(string user, string id, string? path = null, params DateTimeOffset[] restorePoints) => new(
        $"t-{user}-{id}", "thumbnail", "File Explorer thumbnails", EvidenceLevel.Displayed, user, id, path, null,
        OriginalStatus.Unknown, false, null, [], new DateWindow(Jan, Nov, "Low", ["cache file times"]), null,
        RestorePoints: restorePoints.Length == 0 ? null : restorePoints);

    static DateTimeOffset Day(int month, int day) => new(2026, month, day, 9, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Restore_point_copy_tightens_the_window_and_raises_confidence()
    {
        var live = Assert.Single(DateCorroborator.Apply([Thumb("bob", "aa", null, Day(5, 1), Day(3, 10))]));
        Assert.Equal(Day(3, 10), live.Dates!.Before);
        Assert.Equal("High", live.Dates.Confidence);
        Assert.Contains(live.Dates.Sources, s => s.Contains("restore point from 2026-03-10"));
    }

    [Fact]
    public void Restore_point_older_than_the_window_adds_a_line_but_never_inverts_it()
    {
        var older = new DateTimeOffset(2025, 12, 1, 0, 0, 0, TimeSpan.Zero);   // before the live cache file was created
        var item = Assert.Single(DateCorroborator.Apply([Thumb("bob", "aa", null, older)]));
        Assert.Equal(Jan, item.Dates!.After);
        Assert.Equal(Nov, item.Dates.Before);
        Assert.Equal("Low", item.Dates.Confidence);
        Assert.Contains(item.Dates.Sources, s => s.Contains("2025-12-01"));

        var mixed = Assert.Single(DateCorroborator.Apply([Thumb("bob", "aa", null, older, Day(3, 10))]));
        Assert.Equal(Day(3, 10), mixed.Dates!.Before);                     // the one inside the window tightens it
        Assert.Equal("High", mixed.Dates.Confidence);
    }

    [Fact]
    public void Items_without_restore_points_are_not_affected()
    {
        var items = DateCorroborator.Apply([Thumb("bob", "aa"), Thumb("bob", "bb", null, Day(3, 10))]);
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
