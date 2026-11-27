using PCPorter.Forensics.Images;

namespace PCPorter.Forensics.Tests.Images;

public class WindowsRecallDetectorTests
{
    [Fact]
    public void Nothing_to_report_gives_null()
    {
        using var profile = new TempProfile();
        Assert.Null(WindowsRecallDetector.Detect(profile.Folder));
        Assert.Null(WindowsRecallDetector.Detect(""));
    }

    [Fact]
    public void Recall_and_photos_index_are_noted()
    {
        using var profile = new TempProfile();
        Directory.CreateDirectory(Path.Combine(profile.Folder, @"AppData\Local\CoreAIPlatform.00\UKP"));
        Assert.Equal(WindowsRecallDetector.RecallNote, WindowsRecallDetector.Detect(profile.Folder));

        profile.Write(@"AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalState\MediaDb.v1.sqlite", [0]);
        var notes = WindowsRecallDetector.DetectAll(profile.Folder);
        Assert.Equal([WindowsRecallDetector.RecallNote, WindowsRecallDetector.PhotosIndexNote], notes);
        Assert.Contains("can't be read", WindowsRecallDetector.Detect(profile.Folder));
        Assert.Contains("not pictures anyone viewed", WindowsRecallDetector.Detect(profile.Folder));
    }
}
