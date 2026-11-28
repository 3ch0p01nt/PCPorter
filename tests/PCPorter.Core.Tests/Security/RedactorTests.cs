using PCPorter.Core.Security;

namespace PCPorter.Core.Tests.Security;

public class RedactorTests
{
    [Theory]
    [InlineData("sync.exe --password=Hunter2 --go", "sync.exe --password=*** --go")]
    [InlineData("app.exe pwd: s3cret", "app.exe pwd:***")]
    [InlineData(@"curl https://x.blob.core.windows.net/c/f?sv=2024&sig=AbC%2Bdef&se=1", @"curl https://x.blob.core.windows.net/c/f?sv=2024&sig=***&se=1")]
    [InlineData("tool --token \"abc def\"", "tool --token ***")]
    [InlineData("tool token=\"abc def\"", "tool token=***")]
    [InlineData("Authorization: Bearer eyJhbGciOi.payload.sig", "Authorization: Bearer ***")]
    [InlineData("git clone https://bob:pa55@github.com/x/y", "git clone https://bob:***@github.com/x/y")]
    [InlineData("unlock 123456-234567-345678-456789-567890-678901-789012-890123", "unlock ***")]
    [InlineData("net use Z: \\\\srv\\s /user:bob -p Secret1", "net use Z: \\\\srv\\s /user:bob -p ***")]
    [InlineData("app db_password=abc DB_PWD=x", "app db_password=*** DB_PWD=***")]
    [InlineData("Server=s;User Id=u;Password=p@ss;Database=d", "Server=s;User Id=u;Password=***;Database=d")]
    [InlineData("DefaultEndpointsProtocol=https;AccountName=a;AccountKey=Zm9vYmFy==;EndpointSuffix=x", "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=***;EndpointSuffix=x")]
    [InlineData("Endpoint=sb://n/;SharedAccessKeyName=k;SharedAccessKey=abc=", "Endpoint=sb://n/;SharedAccessKeyName=k;SharedAccessKey=***")]
    [InlineData("backup.exe --password Hunter2 --go", "backup.exe --password *** --go")]
    [InlineData("cmdkey /add:srv /user:bob /pass:Hunter2", "cmdkey /add:srv /user:bob /pass:***")]
    [InlineData("curl -u bob:Hunter2 https://x", "curl -u bob:*** https://x")]
    [InlineData("net user bob Hunter2 /add", "net user bob *** /add")]
    [InlineData("net user bob /delete", "net user bob /delete")]
    [InlineData(@"net use Z: \\srv\s Hunter2 /user:bob", @"net use Z: \\srv\s *** /user:bob")]
    [InlineData("$p = ConvertTo-SecureString 'Hunter2' -AsPlainText -Force", "$p = ConvertTo-SecureString *** -AsPlainText -Force")]
    [InlineData("aws AKIAIOSFODNN7EXAMPLE", "aws ***")]
    [InlineData("t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "t ***")]
    [InlineData("git ghp_abcdefghijklmnopqrstuvwxyz0123456789", "git ***")]
    [InlineData("x glpat-abcdefghijklmnopqrst y", "x *** y")]
    [InlineData("slack xoxb-1234567890-abcdef", "slack ***")]
    [InlineData("schtasks /create /tn Sync /tr c:\\s.exe /ru bob /rp Hunter2 /sc daily", "schtasks /create /tn Sync /tr c:\\s.exe /ru bob /rp *** /sc daily")]
    [InlineData("mysql -u root -pHunter2 shop", "mysql -u root -p*** shop")]
    [InlineData("\"C:\\mysql\\bin\\mysqldump.exe\" -uroot -pS3cr3t shop", "\"C:\\mysql\\bin\\mysqldump.exe\" -uroot -p*** shop")]
    [InlineData("mariadb-dump -h db -p'pa ss' x", "mariadb-dump -h db -p*** x")]
    [InlineData("open https://x/cb?next=%2Fapp%3Ftoken%3Dabc123%26x%3D1", "open https://x/cb?next=%2Fapp%3Ftoken%3D***%26x%3D1")]
    [InlineData("go https://x/?r=https%253A%252F%252Fy%253Fpassword%253DHunter2%2526a%253Db", "go https://x/?r=https%253A%252F%252Fy%253Fpassword%253D***%2526a%253Db")]
    [InlineData("go https://x/?r=%2Fa%3Fclient_secret%3Ds%252Bx end", "go https://x/?r=%2Fa%3Fclient_secret%3D*** end")]
    // Start positions the linear-time patterns must still find.
    [InlineData("curl -H x-api-key=abc a__password=b", "curl -H x-api-key=*** a__password=***")]
    [InlineData("go https://x/?r=%2Fa%3F_password%3Dabc end", "go https://x/?r=%2Fa%3F_password%3D*** end")]
    [InlineData("go https://x/?r=%2Fa%3Fx_token%3Dabc end", "go https://x/?r=%2Fa%3Fx_token%3D*** end")]
    [InlineData("open 1.svn+ssh://bob:pa55@h/x", "open 1.svn+ssh://bob:***@h/x")]
    [InlineData("mysql mysql -u r -pA | mysqldump -pB; mysql x & mysql -pC", "mysql mysql -u r -p*** | mysqldump -p***; mysql x & mysql -p***")]
    [InlineData("t =eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "t =***")]
    public void Masks_secrets(string input, string expected) => Assert.Equal(expected, Redactor.Redact(input));

    [Theory]
    [InlineData(@"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background")]
    [InlineData("powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")]   // evidence: kept
    [InlineData("")]
    [InlineData("monkey=banana keyboard.exe /passive")]
    [InlineData("net user")]
    [InlineData("mysql -h db -P3306 -u root shop")]                // capital -P is the port
    [InlineData("tool.exe -protocol tcp")]                         // -p glued text outside a MySQL client
    [InlineData("open https://x/?q=keyboard%3Dnice%26monkey%3Dbanana")]
    public void Leaves_benign_text_alone(string input) => Assert.Equal(input, Redactor.Redact(input));

    // Crafted titles/URLs/command lines from an infected old drive must not make the masking regexes backtrack for hours.
    public static TheoryData<string, string> Adversarial => new()
    {
        { "prefix chain", "a_" },          // (?:[A-Za-z0-9]+[_-])* before the secret names
        { "dash chain", "a-" },
        { "url scheme", "a." },            // [a-z][a-z0-9+.-]*:// at every word start
        { "mysql", "mysql " },             // a lazy scan to the end of the line from every "mysql"
        { "jwt", "eyJ-" },                 // eyJ[...]{8,}\. from every "eyJ"
        { "encoded", "%25" },              // %(?:25)* in the encoded name/value look-arounds
        { "encoded name", "a%3Fa_" },
    };

    [Theory]
    [MemberData(nameof(Adversarial))]
    public void Adversarial_megabyte_finishes_fast(string name, string unit)
    {
        var text = Repeat(unit, 1024 * 1024);
        var cpu = CpuOf(() => Redactor.Redact(text));
        Assert.True(cpu < TimeSpan.FromSeconds(1), $"{name}: {cpu.TotalMilliseconds:0} ms of processor time");
    }

    // The cap alone would hide slow patterns; text right at the cap must be linear too.
    [Theory]
    [MemberData(nameof(Adversarial))]
    public void Adversarial_text_at_the_cap_is_linear(string name, string unit)
    {
        var text = Repeat(unit, Redactor.MaxLength);
        var cpu = CpuOf(() => Redactor.Redact(text));
        Assert.True(cpu < TimeSpan.FromMilliseconds(150), $"{name}: {cpu.TotalMilliseconds:0} ms of processor time");
    }

    [Fact]
    public void Long_text_is_cut_after_the_cap_and_says_so()
    {
        var text = "run --password=Hunter2 " + new string('x', 40_000) + " token=Secret9";
        var r = Redactor.Redact(text);
        Assert.StartsWith("run --password=*** ", r);
        Assert.DoesNotContain("Hunter2", r);
        Assert.DoesNotContain("Secret9", r);
        Assert.EndsWith($"[... {text.Length - Redactor.MaxLength} characters not shown]", r);
        Assert.True(r.Length < Redactor.MaxLength + 100);
    }

    [Fact]
    public void Text_at_the_cap_is_not_cut() =>
        Assert.Equal(new string('x', Redactor.MaxLength), Redactor.Redact(new string('x', Redactor.MaxLength)));

    [Fact]
    public void A_regex_timeout_hides_the_whole_value()
    {
        var r = Redactor.Redact("tool --pass Hunter2", _ => throw new System.Text.RegularExpressions.RegexMatchTimeoutException());
        Assert.DoesNotContain("Hunter2", r);
        Assert.DoesNotContain("tool", r);
    }

    static string Repeat(string unit, int length)
    {
        var sb = new System.Text.StringBuilder(length + unit.Length);
        while (sb.Length < length) sb.Append(unit);
        return sb.ToString(0, length);
    }

    /// <summary>Processor time of the thread that runs <paramref name="work"/> (not wall clock: the suite runs in parallel).
    /// A run still busy after 20 s counts as 20 s, so a hang fails instead of stalling the suite.</summary>
    static TimeSpan CpuOf(Action work)
    {
        var cpu = TimeSpan.MaxValue;
        var t = new Thread(() =>
        {
            var before = ThreadCpu();
            work();
            cpu = ThreadCpu() - before;
        }) { IsBackground = true };
        t.Start();
        return t.Join(TimeSpan.FromSeconds(20)) ? cpu : TimeSpan.FromSeconds(20);
    }

    static TimeSpan ThreadCpu()
    {
        GetThreadTimes(GetCurrentThread(), out _, out _, out var kernel, out var user);
        return TimeSpan.FromTicks(kernel + user);
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool GetThreadTimes(IntPtr thread, out long creation, out long exit, out long kernel, out long user);
}
