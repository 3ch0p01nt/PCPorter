using PCPorter.Core.Case;

namespace PCPorter.Core.Tests.Case;

public class CaseLocationTests
{
    static readonly Dictionary<string, string?> Env = new()
    {
        ["OneDrive"] = @"C:\Users\bob\OneDrive - Contoso",
        ["OneDriveConsumer"] = @"C:\Users\bob\OneDrive",
    };
    static CaseLocationResult Check(string p) => CaseLocation.Check(p, n => Env.GetValueOrDefault(n));

    [Theory]
    [InlineData(@"C:\Users\bob\OneDrive - Contoso\Cases")]
    [InlineData(@"c:\users\bob\onedrive\cases")]
    [InlineData(@"C:\Users\bob\Dropbox\cases")]
    [InlineData(@"C:\Users\bob\Dropbox (Contoso)\cases")]
    [InlineData(@"C:\Users\bob\Google Drive\cases")]
    [InlineData(@"\\server\share\cases")]
    [InlineData(@"D:\Users\alice\OneDrive - Fabrikam\Cases")]   // another user's OneDrive (env vars point elsewhere)
    [InlineData(@"D:\Users\alice\OneDrive\Cases")]
    public void Synced_or_network_folders_are_rejected(string path)
    {
        var r = Check(path);
        Assert.False(r.IsAllowed);
        Assert.False(string.IsNullOrWhiteSpace(r.Reason));
    }

    [Theory]
    [InlineData(@"E:\PCPorter")]
    [InlineData(@"C:\PCPorterDev")]
    [InlineData(@"C:\Users\bob\OneDriveNotReally\x")]
    public void Local_or_external_folders_are_allowed(string path) => Assert.True(Check(path).IsAllowed);
}
