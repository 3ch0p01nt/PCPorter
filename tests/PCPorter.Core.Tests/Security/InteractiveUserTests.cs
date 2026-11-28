using System.Security.Principal;
using PCPorter.Core.Case;
using PCPorter.Core.Security;

namespace PCPorter.Core.Tests.Security;

public class InteractiveUserTests
{
    static readonly Account Admin = new(new SecurityIdentifier("S-1-5-21-1-2-3-500"), @"FAMILY-PC\Dad", @"C:\Users\Dad");
    static readonly Account Kid = new(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), @"FAMILY-PC\Sam", @"C:\Users\Sam");

    [Fact]
    public void Same_account_has_no_note_and_one_case_owner()
    {
        var a = InteractiveUser.Decide(Kid, Kid with { });
        Assert.False(a.Differ);
        Assert.Null(a.Note);
        Assert.Equal([Kid.Sid], a.CaseOwners);
    }

    [Fact]
    public void Another_admin_at_UAC_works_for_the_signed_in_user_and_says_so()
    {
        var a = InteractiveUser.Decide(Admin, Kid);
        Assert.True(a.Differ);
        Assert.Equal(Kid, a.SignedIn);
        Assert.Equal(Admin, a.Process);
        Assert.Equal("Checking the account of Sam (PCPorter was started with Dad's password).", a.Note);
        Assert.Equal([Kid.Sid, Admin.Sid], a.CaseOwners);            // both can open the results
    }

    [Fact]
    public void Unknown_session_user_or_profile_falls_back_to_the_process_account()
    {
        Assert.Equal(Admin, InteractiveUser.Decide(Admin, null).SignedIn);
        Assert.Equal(Admin, InteractiveUser.Decide(Admin, Kid with { ProfilePath = null }).SignedIn);
        Assert.Null(InteractiveUser.Decide(Admin, null).Note);
    }

    [Fact]
    public void Case_folder_is_private_to_both_accounts()
    {
        var sids = CaseFolder.PrivateSids(InteractiveUser.Decide(Admin, Kid)).ToList();
        Assert.Contains(Kid.Sid, sids);
        Assert.Contains(Admin.Sid, sids);
        Assert.Contains(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), sids);
        Assert.Contains(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), sids);
        Assert.Equal(4, sids.Count);
    }

    [Fact]
    public void Short_name_drops_the_domain() => Assert.Equal("Sam", Kid.ShortName);

    [Fact]
    public void This_process_finds_its_own_session_user()
    {
        // Tests run non-elevated as the signed-in user: both are this account, with its profile folder.
        var a = InteractiveUser.Current;
        Assert.Equal(WindowsIdentity.GetCurrent().User, a.Process.Sid);
        Assert.False(a.Differ);
        Assert.NotNull(a.SignedIn.ProfilePath);
        Assert.True(Directory.Exists(a.SignedIn.ProfilePath));
    }
}
