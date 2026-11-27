using System.Text.RegularExpressions;

namespace PCPorter.Core.Security;

/// <summary>
/// Masks secrets that turn up in command lines, Run keys and task arguments before they reach logs or reports:
/// name=value / name:value secrets (also with prefixes like db_password, connection-string parts like AccountKey),
/// the same names URL-encoded inside query strings, --password X style switches (and schtasks /rp), mysql -pX, cmdkey /pass:, curl -u, net user / net use passwords, ConvertTo-SecureString text,
/// Bearer/Basic headers, URL user:password, well-known token shapes (AWS, JWT, GitHub, GitLab, Slack, OpenAI-style)
/// and BitLocker recovery keys. Encoded PowerShell (-enc ...) is kept: it is evidence, not a credential.
/// </summary>
public static partial class Redactor
{
    const string Mask = "***";
    const string Value = @"(""[^""]*""|'[^']*'|[^\s&;""']+)";

    // Secret names. The look-behind allows a prefix joined by _ or - (db_password, x-api-key) but not a longer word (monkey=).
    const string NameList = @"((?:[A-Za-z0-9]+[_-])*(?:password|passwd|passphrase|pwd|pass|token|access_token|refresh_token|" +
                            @"api[_-]?key|apikey|secret|client_secret|sig|key|accountkey|sharedaccesskey|credential|auth))";
    const string Names = @"(?<![A-Za-z0-9])" + NameList;

    [GeneratedRegex(Names + @"\s*([=:])\s*" + Value, RegexOptions.IgnoreCase)]
    private static partial Regex KeyValue();

    // The same names inside a URL-encoded query string (once or more: %3D, %253D ...), e.g. ?next=%2Fcb%3Ftoken%3Dabc%26x%3D1.
    // The name may follow an escape (%3F, %26); the value ends at an encoded &, ;, space, quote or #.
    [GeneratedRegex(@"(?<=^|[^A-Za-z0-9]|%(?:25)*[0-9A-Fa-f]{2})" + NameList + @"(%(?:25)*3[Dd])((?:(?!%(?:25)*(?:26|3[Bb]|20|22|27|23))[^\s&;""'#])+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex EncodedKeyValue();

    [GeneratedRegex(@"(?i)(\s(?:--?|/)(?:p|rp|pw|pass|password|passwd|passphrase|token|secret|api-?key|apikey)\s+)" + Value)]
    private static partial Regex PasswordSwitch();

    // MySQL/MariaDB clients take the password glued to the switch: mysql -u root -pHunter2 (capital -P is the port).
    [GeneratedRegex(@"(?i)(\b(?:mysql[a-z]*|mariadb(?:-[a-z]+)?)(?:\.exe)?""?\s(?:[^\r\n|&;]*?\s)?(?-i:-p))(?!\s)" + Value)]
    private static partial Regex MySqlPassword();

    [GeneratedRegex(@"(?i)((?:\s-u|\s--user)\s+[^\s:]+:)(\S+)")]
    private static partial Regex CurlUser();

    [GeneratedRegex(@"(?i)(\bnet1?(?:\.exe)?\s+user\s+(?:""[^""]+""|\S+)\s+)(?![/*])(\S+)")]
    private static partial Regex NetUser();

    [GeneratedRegex(@"(?i)(\bnet1?(?:\.exe)?\s+use\s+(?:[a-z]:\s+|\*\s+)?\\\\\S+\s+)(?![/*])(\S+)")]
    private static partial Regex NetUse();

    [GeneratedRegex(@"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)" + Value)]
    private static partial Regex SecureStringText();

    [GeneratedRegex(@"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*")]
    private static partial Regex AuthHeader();

    [GeneratedRegex(@"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")]
    private static partial Regex UrlUserInfo();

    [GeneratedRegex(@"\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|" +
                    @"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|" +
                    @"xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})")]
    private static partial Regex KnownToken();

    [GeneratedRegex(@"\b\d{6}(-\d{6}){7}\b")]
    private static partial Regex BitLockerKey();

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var s = BitLockerKey().Replace(text, Mask);
        s = KnownToken().Replace(s, Mask);
        s = UrlUserInfo().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + ":" + Mask + "@");
        s = AuthHeader().Replace(s, m => m.Groups[1].Value + " " + Mask);
        s = KeyValue().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + Mask);
        s = EncodedKeyValue().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + Mask);
        s = PasswordSwitch().Replace(s, m => m.Groups[1].Value + Mask);
        s = MySqlPassword().Replace(s, m => m.Groups[1].Value + Mask);
        s = CurlUser().Replace(s, m => m.Groups[1].Value + Mask);
        s = NetUser().Replace(s, m => m.Groups[1].Value + Mask);
        s = NetUse().Replace(s, m => m.Groups[1].Value + Mask);
        s = SecureStringText().Replace(s, m => m.Groups[1].Value + Mask);
        return s;
    }
}
