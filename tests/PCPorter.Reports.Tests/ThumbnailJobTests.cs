using PCPorter.Forensics.Gallery;
using PCPorter.Forensics.Images;
using PCPorter.Forensics.Thumbcache;
using PCPorter.Reports;

namespace PCPorter.Reports.Tests;

public class ThumbnailJobTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-job").FullName;
    public void Dispose() { try { Directory.Delete(_root, true); } catch (IOException) { } }

    static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];

    string Out => Path.Combine(_root, "out");

    ThumbnailSource Live(string user = "bob")
    {
        var dir = Path.Combine(_root, "Users", user, "AppData", "Local", "Microsoft", "Windows", "Explorer");
        Directory.CreateDirectory(dir);
        return new ThumbnailSource(user, dir);
    }

    /// <summary>Yields pictures, running <paramref name="midway"/> after the first one was handed over.</summary>
    sealed class PictureSource(Action? midway = null, int count = 3) : IImageEvidenceSource
    {
        public string Name => "Fake pictures";
        public IEnumerable<ImageEvidence> Collect(ImageSourceContext context, CancellationToken cancellationToken = default)
        {
            for (int n = 0; n < count; n++)
            {
                byte[] bytes = [.. Png, (byte)n];
                yield return new ImageEvidence("Screenshots folder", EvidenceLevel.OnScreen, context.User, $@"C:\Pics\p{n}.png", null,
                    DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, "created", bytes, "image/png");
                if (n == 0) midway?.Invoke();
            }
        }
    }

    IEnumerable<string> CaseFolders() =>
        Directory.Exists(Path.Combine(Out, "PCPorter")) ? Directory.EnumerateDirectories(Path.Combine(Out, "PCPorter")) : [];

    [Fact]
    public void Cancel_after_pictures_were_extracted_leaves_no_case_folder()
    {
        using var cts = new CancellationTokenSource();
        var options = new ThumbnailJobOptions(ExtraSources: [new PictureSource(cts.Cancel)]);
        Assert.ThrowsAny<OperationCanceledException>(() =>
            ThumbnailJob.Run(Out, new NoPathResolver(), [Live()], options: options, ct: cts.Token));
        Assert.Empty(CaseFolders());
    }

    [Fact]
    public void Failure_before_the_report_leaves_no_case_folder()
    {
        var options = new ThumbnailJobOptions(ExtraSources: [new PictureSource()],
            DuplicateGrouper: (_, folder, _) => { Assert.NotEmpty(Directory.GetFiles(folder)); throw new InvalidOperationException("boom"); });
        Assert.Throws<InvalidOperationException>(() => ThumbnailJob.Run(Out, new NoPathResolver(), [Live()], options: options));
        Assert.Empty(CaseFolders());
    }

    [Fact]
    public void Finished_run_keeps_the_report_and_pictures_but_not_the_work_folder()
    {
        var r = ThumbnailJob.Run(Out, new NoPathResolver(), [Live()], options: new ThumbnailJobOptions(ExtraSources: [new PictureSource()]));
        Assert.True(File.Exists(r.ReportPath));
        Assert.Equal(3, Directory.GetFiles(Path.Combine(r.CaseFolder, "Thumbnails", "thumbs")).Length);
        Assert.False(Directory.Exists(Path.Combine(r.CaseFolder, "work")));
    }
}
