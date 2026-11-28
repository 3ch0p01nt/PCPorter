using System.Text;
using System.Text.RegularExpressions;

namespace PCPorter.Core.Security;

/// <summary>
/// Masks secrets that turn up in command lines, Run keys and task arguments before they reach logs or reports:
/// name=value / name:value secrets (also with prefixes like db_password, connection-string parts like AccountKey),
/// the same names URL-encoded inside query strings, --password X style switches (and schtasks /rp), mysql -pX, cmdkey /pass:, curl -u, net user / net use passwords, ConvertTo-SecureString text,
/// Bearer/Basic headers, URL user:password, well-known token shapes (AWS, JWT, GitHub, GitLab, Slack, OpenAI-style)
/// and BitLocker recovery keys. Encoded PowerShell (-enc ...) is kept: it is evidence, not a credential.
/// </summary>
/// <remarks>
/// The text often comes from an old PC that may be infected, so it is hostile: only the first <see cref="MaxLength"/>
/// characters are kept, every pattern is written to run in linear time (no start position inside a run that an earlier
/// start already covers, atomic groups, bounded repeats), and every regex has a time limit. If a limit is hit anyway,
/// the whole value is hidden (fail closed) rather than shown unmasked.
/// </remarks>
public static partial class Redactor
{
    const string Mask = "***";
    const string Unchecked = "[not shown: too complex to check for passwords]";
    const int TimeoutMs = 500;
    const string Value = @"(""[^""]*""|'[^']*'|[^\s&;""']+)";

    /// <summary>Longer text is cut here (the rest is replaced by a note saying how much was left out).</summary>
    internal const int MaxLength = 16 * 1024;

    // Secret names, with a prefix joined by _ or - (db_password, x-api-key) but not a longer word (monkey=). Each prefix
    // segment is atomic: it ends at the _ or -, so there is nothing to retry inside it.
    const string NameList = @"((?:(?>[A-Za-z0-9]+)[_-])*(?:password|passwd|passphrase|pwd|pass|token|access_token|refresh_token|" +
                            @"api[_-]?key|apikey|secret|client_secret|sig|key|accountkey|sharedaccesskey|credential|auth))";

    // A name starts at the start of its identifier: not after a letter/digit, and not after "x_" / "x-" (that start is
    // inside a prefix chain the earlier start already tries, and retrying it at every _ made a_a_a_... quadratic).
    const string Names = @"(?<![A-Za-z0-9]|[A-Za-z0-9][_-])" + NameList;

    [GeneratedRegex(Names + @"\s*([=:])\s*" + Value, RegexOptions.IgnoreCase, TimeoutMs)]
    private static partial Regex KeyValue();

    // The same names inside a URL-encoded query string (once or more: %3D, %253D ...), e.g. ?next=%2Fcb%3Ftoken%3Dabc%26x%3D1.
    // The name may follow an escape (%3F, %26), also with a _ or - between; the value ends at an encoded &, ;, space,
    // quote or #. Up to eight levels of %25 encoding (unbounded, %252525... made each look-around scan the whole run).
    const string Esc = @"%(?:25){0,8}";

    [GeneratedRegex(@"(?<=^|[^A-Za-z0-9_-]|(?<![A-Za-z0-9])[_-]|" + Esc + @"[0-9A-Fa-f]{2}[_-]?)" + NameList +
                    @"(" + Esc + @"3[Dd])((?:(?!" + Esc + @"(?:26|3[Bb]|20|22|27|23))[^\s&;""'#])+)",
        RegexOptions.IgnoreCase, TimeoutMs)]
    private static partial Regex EncodedKeyValue();

    [GeneratedRegex(@"(?i)(\s(?:--?|/)(?:p|rp|pw|pass|password|passwd|passphrase|token|secret|api-?key|apikey)\s+)" + Value, RegexOptions.None, TimeoutMs)]
    private static partial Regex PasswordSwitch();

    // MySQL/MariaDB clients take the password glued to the switch: mysql -u root -pHunter2 (capital -P is the port).
    // MySqlClient finds the program; MySqlPassword (anchored with \G) then looks for -p in the rest of that command.
    [GeneratedRegex(@"(?i)\b(?:mysql[a-z]*|mariadb(?:-[a-z]+)?)(?:\.exe)?""?\s", RegexOptions.None, TimeoutMs)]
    private static partial Regex MySqlClient();

    [GeneratedRegex(@"\G(?i)(\b(?:mysql[a-z]*|mariadb(?:-[a-z]+)?)(?:\.exe)?""?\s(?:[^\r\n|&;]*?\s)?(?-i:-p))(?!\s)" + Value, RegexOptions.None, TimeoutMs)]
    private static partial Regex MySqlPassword();

    [GeneratedRegex(@"(?i)((?:\s-u|\s--user)\s+[^\s:]+:)(\S+)", RegexOptions.None, TimeoutMs)]
    private static partial Regex CurlUser();

    [GeneratedRegex(@"(?i)(\bnet1?(?:\.exe)?\s+user\s+(?:""[^""]+""|\S+)\s+)(?![/*])(\S+)", RegexOptions.None, TimeoutMs)]
    private static partial Regex NetUser();

    [GeneratedRegex(@"(?i)(\bnet1?(?:\.exe)?\s+use\s+(?:[a-z]:\s+|\*\s+)?\\\\\S+\s+)(?![/*])(\S+)", RegexOptions.None, TimeoutMs)]
    private static partial Regex NetUse();

    [GeneratedRegex(@"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)" + Value, RegexOptions.None, TimeoutMs)]
    private static partial Regex SecureStringText();

    [GeneratedRegex(@"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.None, TimeoutMs)]
    private static partial Regex AuthHeader();

    // user:password@ right after "://". The scheme is not part of the match: matching it from every word start made
    // a.a.a... quadratic, and any scheme (or none) is masked the same way.
    [GeneratedRegex(@"(://)([^/\s:@]+):([^/\s@]+)@", RegexOptions.None, TimeoutMs)]
    private static partial Regex UrlUserInfo();

    // A JWT does not start right after "-" (that start is inside the run an earlier eyJ already scanned: eyJ-eyJ-...).
    [GeneratedRegex(@"\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|(?<!-)eyJ(?>[A-Za-z0-9_-]{8,})\.(?>[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}|" +
                    @"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|" +
                    @"xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})", RegexOptions.None, TimeoutMs)]
    private static partial Regex KnownToken();

    [GeneratedRegex(@"\b\d{6}(-\d{6}){7}\b", RegexOptions.None, TimeoutMs)]
    private static partial Regex BitLockerKey();

    public static string Redact(string? text) => Redact(text, MaskAll);

    /// <summary>Caps <paramref name="text"/>, runs <paramref name="apply"/> on it and hides everything on a regex timeout.</summary>
    internal static string Redact(string? text, Func<string, string> apply)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var cut = text.Length > MaxLength;
        var head = cut ? text[..MaxLength] : text;
        string masked;
        try { masked = apply(head); }
        catch (RegexMatchTimeoutException) { return Unchecked; }
        return cut ? masked + $" [... {text.Length - MaxLength} characters not shown]" : masked;
    }

    static string MaskAll(string text)
    {
        var s = BitLockerKey().Replace(text, Mask);
        s = KnownToken().Replace(s, Mask);
        s = UrlUserInfo().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + ":" + Mask + "@");
        s = AuthHeader().Replace(s, m => m.Groups[1].Value + " " + Mask);
        s = KeyValue().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + Mask);
        s = EncodedKeyValue().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + Mask);
        s = PasswordSwitch().Replace(s, m => m.Groups[1].Value + Mask);
        s = MaskMySql(s);
        s = CurlUser().Replace(s, m => m.Groups[1].Value + Mask);
        s = NetUser().Replace(s, m => m.Groups[1].Value + Mask);
        s = NetUse().Replace(s, m => m.Groups[1].Value + Mask);
        s = SecureStringText().Replace(s, m => m.Groups[1].Value + Mask);
        return s;
    }

    /// <summary>
    /// Same result as Replace with the unanchored MySQL pattern, in linear time: when no -p follows a client name in
    /// its command (up to a line break, |, &amp; or ;), no later client name in that command can have one either, so
    /// the search skips to the next command instead of rescanning it from every "mysql".
    /// </summary>
    static string MaskMySql(string s)
    {
        StringBuilder? sb = null;
        int copied = 0, pos = 0;
        while (pos < s.Length)
        {
            var client = MySqlClient().Match(s, pos);
            if (!client.Success) break;
            var m = MySqlPassword().Match(s, client.Index);
            if (m.Success)
            {
                var keep = m.Groups[1];
                (sb ??= new StringBuilder(s.Length)).Append(s, copied, keep.Index + keep.Length - copied).Append(Mask);
                copied = pos = m.Index + m.Length;
            }
            else
            {
                var end = s.AsSpan(client.Index + client.Length).IndexOfAny("\r\n|&;");
                pos = end < 0 ? s.Length : client.Index + client.Length + end + 1;
            }
        }
        return sb is null ? s : sb.Append(s, copied, s.Length - copied).ToString();
    }
}
