using PCPorter.Forensics.BrowserHistory;

namespace PCPorter.Forensics.Tests.BrowserHistory;

public class BrowserProfileFinderTests
{
    [Fact]
    public void Finds_every_supported_profile_in_a_stable_order()
    {
        var home = BrowserFixtures.TempDir();
        try
        {
            const string chrome = @"AppData\Local\Google\Chrome\User Data";
            BrowserFixtures.Touch(home, chrome + @"\Default\History");
            BrowserFixtures.Touch(home, chrome + @"\Profile 2\History");
            BrowserFixtures.Touch(home, chrome + @"\Guest Profile\History");
            BrowserFixtures.Touch(home, chrome + @"\System Profile\History");
            BrowserFixtures.Touch(home, chrome + @"\Profile 3\Preferences");          // no History: ignored
            BrowserFixtures.Touch(home, chrome + @"\Local State", BrowserFixtures.LocalState(("Default", "Bob"), ("Profile 2", "Work")));
            BrowserFixtures.Touch(home, @"AppData\Local\Microsoft\Edge\User Data\Default\History");
            BrowserFixtures.Touch(home, @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History");
            BrowserFixtures.Touch(home, @"AppData\Roaming\Opera Software\Opera Stable\History");
            BrowserFixtures.Touch(home, @"AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\places.sqlite");
            BrowserFixtures.Touch(home, @"AppData\Roaming\Mozilla\Firefox\Profiles\efgh.empty\prefs.js");   // no places: ignored
            BrowserFixtures.Touch(home, @"AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat");

            var warnings = new List<string>();
            var found = BrowserProfileFinder.Find("bob", home, warnings);

            var expected = new[]
            {
                ("Brave", BrowserFamily.Chromium, "Default", @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"),
                ("Firefox", BrowserFamily.Firefox, "default-release", @"AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release"),
                ("Google Chrome", BrowserFamily.Chromium, "Bob", chrome + @"\Default"),
                ("Google Chrome", BrowserFamily.Chromium, "Work", chrome + @"\Profile 2"),
                ("Internet Explorer / Edge (legacy)", BrowserFamily.WebCache, "Default", @"AppData\Local\Microsoft\Windows\WebCache"),
                ("Microsoft Edge", BrowserFamily.Chromium, "Default", @"AppData\Local\Microsoft\Edge\User Data\Default"),
                ("Opera", BrowserFamily.Chromium, "Default", @"AppData\Roaming\Opera Software\Opera Stable"),
            };
            Assert.Equal(expected.Select(e => new BrowserProfile("bob", e.Item1, e.Item2, e.Item3, Path.Combine(home, e.Item4))), found);
            Assert.Empty(warnings);
        }
        finally { BrowserFixtures.Delete(home); }
    }

    [Fact]
    public void Corrupt_local_state_falls_back_to_folder_names_with_a_warning()
    {
        var home = BrowserFixtures.TempDir();
        try
        {
            BrowserFixtures.Touch(home, @"AppData\Local\Vivaldi\User Data\Profile 1\History");
            BrowserFixtures.Touch(home, @"AppData\Local\Vivaldi\User Data\Local State", "{ not json");
            var warnings = new List<string>();
            var found = Assert.Single(BrowserProfileFinder.Find("bob", home, warnings));
            Assert.Equal("Vivaldi", found.Browser);
            Assert.Equal("Profile 1", found.Name);
            Assert.Single(warnings);
        }
        finally { BrowserFixtures.Delete(home); }
    }

    [Fact]
    public void A_profile_folder_with_no_browsers_finds_nothing()
    {
        var home = BrowserFixtures.TempDir();
        try { Assert.Empty(BrowserProfileFinder.Find("bob", home, new List<string>())); }
        finally { BrowserFixtures.Delete(home); }
    }
}
