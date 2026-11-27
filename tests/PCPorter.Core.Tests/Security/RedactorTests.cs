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
}
