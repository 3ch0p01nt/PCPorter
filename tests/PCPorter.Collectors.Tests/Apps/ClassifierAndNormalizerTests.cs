using PCPorter.Collectors.Apps;

namespace PCPorter.Collectors.Tests.Apps;

public class AppNameNormalizerTests
{
    [Theory]
    [InlineData("7-Zip 23.01 (x64)", "7-zip")]
    [InlineData("Python 3.12.1 (64-bit)", "python")]
    [InlineData("Microsoft 365 Apps for enterprise - en-us", "microsoft 365 apps for enterprise")]
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", "microsoft visual c++ 2015-2022 redistributable")]
    [InlineData("Adobe Acrobat® Reader DC", "adobe acrobat reader dc")]
    [InlineData("Contoso™ Tool  v2.1.0", "contoso tool")]
    [InlineData("  Spaced    Out   Name ", "spaced out name")]
    [InlineData("Git version 2.43.0", "git")]
    [InlineData("Node.js", "node.js")]
    [InlineData("Microsoft .NET Runtime - 8.0.1 (x86)", "microsoft .net runtime")]
    [InlineData("WinRAR 6.24 (32-bit)", "winrar")]
    [InlineData("Microsoft Office 2016", "microsoft office 2016")]
    [InlineData("1.2.3", "1.2.3")]
    public void Normalizes(string input, string expected) => Assert.Equal(expected, AppNameNormalizer.Normalize(input));

    [Fact]
    public void Empty_is_empty() => Assert.Equal("", AppNameNormalizer.Normalize(null));

    [Fact]
    public void Match_key_drops_parentheses_and_punctuation() =>
        Assert.Equal("mozillafirefox", AppNameNormalizer.MatchKey("Mozilla Firefox (x64 en-US)"));

    [Fact]
    public void Long_non_matching_names_do_not_hang()
    {
        var name = "abc 1.2" + new string('a', 5000) + "!";
        var sw = System.Diagnostics.Stopwatch.StartNew();
        _ = AppNameNormalizer.Normalize(name);
        Assert.True(sw.ElapsedMilliseconds < 1000);
    }
}

public class AppClassifierTests
{
    static AppKind K(string name, string? location = null, params string[] libs) => AppClassifier.Classify(name, location, libs);

    [Theory]
    [InlineData("VcRedist", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135")]
    [InlineData("VcRedist", "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.29.30133")]
    [InlineData("DotNet", "Microsoft .NET Runtime - 8.0.1 (x64)")]
    [InlineData("DotNet", "Microsoft .NET Desktop Runtime - 6.0.25 (x64)")]
    [InlineData("AspNetCore", "Microsoft ASP.NET Core 8.0.1 - Shared Framework (x64)")]
    [InlineData("WindowsDesktopRuntime", "Microsoft Windows Desktop Runtime - 8.0.1 (x64)")]
    [InlineData("DirectX", "Microsoft DirectX for Managed Code")]
    [InlineData("WebView2", "Microsoft Edge WebView2 Runtime")]
    [InlineData("Edge", "Microsoft Edge")]
    [InlineData("Edge", "Microsoft Edge Update")]
    [InlineData("UpdateHealthTools", "Microsoft Update Health Tools")]
    [InlineData("GameInput", "Microsoft GameInput")]
    public void Each_runtime_pattern_matches(string pattern, string name)
    {
        Assert.Matches(AppClassifier.RuntimePatterns[pattern], name);
        Assert.Equal(AppKind.Runtime, K(name));
    }

    [Theory]
    [InlineData("Microsoft Edge Dev")]
    [InlineData("Microsoft Visual Studio Code")]
    [InlineData("Visual C++ Build Tools")]
    public void Look_alikes_are_not_runtimes(string name) => Assert.NotEqual(AppKind.Runtime, K(name));

    [Theory]
    [InlineData("NVIDIA Graphics Driver 551.23")]
    [InlineData("NVIDIA HD Audio Driver 1.4.0.1")]
    [InlineData("AMD Chipset Software")]
    [InlineData("Realtek High Definition Audio Driver")]
    [InlineData("Intel(R) Management Engine Components")]
    [InlineData("Intel(R) Chipset Device Software")]
    public void Drivers(string name) => Assert.Equal(AppKind.Driver, K(name));

    [Theory]
    [InlineData("NVIDIA GeForce Experience 3.27")]
    [InlineData("Intel Driver & Support Assistant")]          // no "(R)": a normal app
    [InlineData("AMD Ryzen Master")]
    public void Vendor_apps_that_are_not_drivers(string name) => Assert.Equal(AppKind.Win32, K(name));

    [Fact]
    public void Steam_app_names_are_games()
    {
        Assert.Equal(AppKind.Game, K("Steam App 440"));
        Assert.Equal(AppKind.Win32, K("Steam App"));
    }

    [Fact]
    public void Install_location_under_a_game_library_is_a_game()
    {
        Assert.Equal(AppKind.Game, K("Some Game", @"D:\SteamLibrary\steamapps\common\Some Game\", @"D:\SteamLibrary\steamapps"));
        Assert.Equal(AppKind.Game, K("Epic Thing", @"C:\Program Files\Epic Games\Thing", @"C:\Program Files\Epic Games"));
        Assert.Equal(AppKind.Win32, K("Near Miss", @"D:\SteamLibraryX\app", @"D:\SteamLibrary"));
        Assert.Equal(AppKind.Win32, K("No Location", null, @"D:\SteamLibrary"));
    }
}
