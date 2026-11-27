using System.Text;
using PCPorter.Collectors.Apps;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Apps;

/// <summary>A scanned PC's drive in a temp folder ("C:\" on the scanned PC maps to <see cref="Root"/>).</summary>
public sealed class FakeDrive : IDisposable
{
    public string Root { get; } = Directory.CreateTempSubdirectory("pcporter-apps").FullName + "\\";
    public string Work => Path.Combine(Root, "_work");

    /// <summary>Path on the fake drive for a scanned-PC path like C:\ProgramData\x.</summary>
    public string At(string scannedPcPath) => Path.Combine(Root, scannedPcPath[3..]);

    public string Write(string scannedPcPath, string text)
    {
        var p = At(scannedPcPath);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, text);
        return p;
    }

    public void Dispose()
    {
        try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

public static class AppTest
{
    public static readonly UserProfile Bob = new("S-1-5-21-1-2-3-1001", "bob", null, null);

    public static UserProfile BobOn(FakeDrive d) => Bob with { ProfilePath = d.At(@"C:\Users\bob") };

    public static CollectorContext Context(ISystemSource src, string work, List<string>? warnings = null) =>
        new(src, new FakeWmiClient(), new FakeProcessRunner((_, _) => new ProcessResult(0, "", false)), new NoSignatureChecker(), work, warnings ?? []);

    public static (List<InstalledApp> Apps, CollectorOutput Output, List<string> Warnings) Run(ISystemSource src, string work, AppInventoryOptions? options = null)
    {
        var warnings = new List<string>();
        var output = new AppInventoryCollector(options ?? AppInventoryOptions.RegistryOnly).Run(Context(src, work, warnings), CancellationToken.None);
        return (output.Items.Cast<InstalledApp>().ToList(), output, warnings);
    }

    public const string Uninstall = @"Microsoft\Windows\CurrentVersion\Uninstall";
    public const string Uninstall32 = @"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    public const string UserUninstall = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
}
