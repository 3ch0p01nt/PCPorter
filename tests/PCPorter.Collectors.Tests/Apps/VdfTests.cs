using PCPorter.Collectors.Apps;

namespace PCPorter.Collectors.Tests.Apps;

public class VdfTests
{
    public const string LibraryFolders = """
        "libraryfolders"
        {
            "0"
            {
                "path"      "C:\\Program Files (x86)\\Steam"
                "label"     ""
                "apps"
                {
                    "228980"    "123"
                    "440"       "456"
                }
            }
            // a comment
            "1"
            {
                "path"      "C:\\Games\\SteamLib"
            }
            "2"
            {
                "path"      "D:\\SteamLibrary"
            }
        }
        """;

    [Fact]
    public void Parses_nested_library_folders()
    {
        var root = Vdf.Parse(LibraryFolders);
        var lf = root.Child("LibraryFolders");                     // keys are case-insensitive
        Assert.NotNull(lf);
        Assert.Equal(3, lf.Children.Count);
        Assert.Equal(@"C:\Program Files (x86)\Steam", lf.Child("0")!["path"]);
        Assert.Equal("456", lf.Child("0")!.Child("apps")!["440"]);
        Assert.Equal("", lf.Child("0")!["label"]);
        Assert.Equal(@"D:\SteamLibrary", lf.Child("2")!["path"]);
    }

    [Fact]
    public void Escapes_bare_tokens_and_conditionals()
    {
        var root = Vdf.Parse("""
            AppState
            {
                "name" "Say \"Hi\"\tnow"
                appid 440 [$WIN32]
                "x" "y" [$!OSX]
            }
            """);
        var s = root.Child("AppState")!;
        Assert.Equal("Say \"Hi\"\tnow", s["name"]);
        Assert.Equal("440", s["appid"]);
        Assert.Equal("y", s["x"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{{{{")]
    [InlineData("}}}} \"a\"")]
    [InlineData("\"unterminated")]
    [InlineData("\"a\" { \"b\" \"c\"")]
    public void Malformed_input_never_throws(string text) => Assert.NotNull(Vdf.Parse(text));

    [Fact]
    public void Partial_input_keeps_what_was_read() =>
        Assert.Equal("c", Vdf.Parse("\"a\" { \"b\" \"c\"").Child("a")!["b"]);
}
