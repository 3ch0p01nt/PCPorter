using PCPorter.Collectors.Apps;
using Xunit.Abstractions;

namespace PCPorter.Collectors.Tests.Apps;

/// <summary>The port must give winget's own answers: winget's test data (1,137 real names and publishers).</summary>
public class WingetNormalizerTests(ITestOutputHelper output)
{
    static string Data(string file) => Path.Combine(AppContext.BaseDirectory, "Apps", "TestData", "winget-normalization", file);

    [Fact]
    public void Matches_wingets_own_results()
    {
        var names = File.ReadAllLines(Data("InputNames.txt"));
        var publishers = File.ReadAllLines(Data("InputPublishers.txt"));
        var expected = File.ReadAllLines(Data("NormalizationInitialIds.txt"));
        Assert.Equal(names.Length, expected.Length);
        var wrong = new List<string>();
        for (int i = 0; i < names.Length; i++)
        {
            var got = WingetNormalizer.Publisher(publishers[i]) + "." + WingetNormalizer.Name(names[i]).Name;
            if (got != expected[i]) wrong.Add($"[{names[i]}] [{publishers[i]}] -> {got}, winget: {expected[i]}");
        }
        foreach (var w in wrong.Take(40)) output.WriteLine(w);
        Assert.True(wrong.Count == 0, $"{wrong.Count} of {names.Length} differ from winget.");
    }

    [Theory]
    [InlineData("Name", null)]
    [InlineData("Name x86", "X86")]
    [InlineData("Name x86_64", "X64")]
    [InlineData("Name (64 bit)", "X64")]
    [InlineData("Name arm32", "Arm")]
    [InlineData("Name arm64", "Arm64")]
    [InlineData("Name aarch64", "Arm64")]
    [InlineData("Name armadillo", null)]
    [InlineData("Name 32/64 bit", null)]
    [InlineData("Fox86", null)]
    public void Architecture_like_winget(string name, string? arch) => Assert.Equal(arch, WingetNormalizer.Name(name).Architecture);

    [Fact]
    public void Names_and_locales_like_winget()
    {
        Assert.Equal("Namearmadillo", WingetNormalizer.Name("Name armadillo").Name);
        Assert.Equal("ARMCompiler", WingetNormalizer.Name("ARM Compiler (x64)").Name);
        Assert.Equal("en-us", WingetNormalizer.Name("Name en-US").Locale);
        Assert.Equal("es-mx", WingetNormalizer.Name("Name (es-mx)").Locale);
        Assert.Equal("", WingetNormalizer.Name("Names-mx").Locale);
        Assert.Equal("FixforKB42", WingetNormalizer.Name("Fix for (KB42)").Name);
    }
}
