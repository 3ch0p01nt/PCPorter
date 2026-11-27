using System.Text.RegularExpressions;

namespace PCPorter.Collectors.Apps;

/// <summary>Turns display names into a stable comparable form ("7-Zip 23.01 (x64)" -> "7-zip").</summary>
public static partial class AppNameNormalizer
{
    [GeneratedRegex(@"[®™©]")] private static partial Regex Marks();
    [GeneratedRegex(@"\(\s*(x64|x86|amd64|arm64|64-bit|32-bit|64 bit|32 bit)\s*\)", RegexOptions.IgnoreCase)] private static partial Regex ArchTag();
    [GeneratedRegex(@"\s+-\s+[a-z]{2}-[a-z]{2,4}$", RegexOptions.IgnoreCase)] private static partial Regex Locale();
    [GeneratedRegex(@"[\s\-_,]+(version\s+)?v?\d+(\.\d+)+([\-+][a-z0-9.]+)?$", RegexOptions.IgnoreCase)] private static partial Regex TrailingVersion();
    [GeneratedRegex(@"[\s\-–,]+$")] private static partial Regex TrailingJunk();
    [GeneratedRegex(@"\s+")] private static partial Regex Spaces();
    [GeneratedRegex(@"\([^)]*\)")] private static partial Regex Parens();
    [GeneratedRegex(@"[^a-z0-9]")] private static partial Regex NonAlnum();

    public static string Normalize(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var s = Marks().Replace(name, "");
        s = ArchTag().Replace(s, " ");
        s = Spaces().Replace(s, " ").Trim();
        string before;
        do
        {
            before = s;
            s = Locale().Replace(s, "");
            s = TrailingVersion().Replace(s, "");
            s = TrailingJunk().Replace(s, "").Trim();
        } while (s != before && s.Length > 0);
        if (s.Length == 0) s = name.Trim();                      // a name that is only a version: keep it
        return Spaces().Replace(s, " ").Trim().ToLowerInvariant();
    }

    /// <summary>Normalized name without any parenthesised parts and without non-alphanumerics: for loose matching.</summary>
    public static string MatchKey(string? name) => NonAlnum().Replace(Normalize(Parens().Replace(name ?? "", " ")), "");

    /// <summary>Lower-case letters and digits only.</summary>
    public static string Squash(string? s) => NonAlnum().Replace((s ?? "").ToLowerInvariant(), "");
}
