using System.Text;
using System.Text.RegularExpressions;

namespace PCPorter.Collectors.Apps;

/// <summary>
/// A port of winget's own name and publisher normalization ("NormalizationInitial" in winget-cli,
/// src/AppInstallerCommonCore/NameNormalization.cpp, MIT licence). winget's catalog stores names and publishers in this
/// form, so matching an installed app needs exactly the same rules. Checked against winget's own test data
/// (1,137 real names and publishers) in WingetNormalizerTests.
/// ICU differences handled: a case-insensitive \p{Lu} in ICU also matches lower-case letters, so it is written as
/// [\p{Lu}\p{Ll}\p{Lt}] here.
/// </summary>
public static class WingetNormalizer
{
    public sealed record Result(string Name, string? Architecture, string Locale);

    const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    const string Lu = @"[\p{Lu}\p{Ll}\p{Lt}]";
    static Regex R(string pattern) => new(
        pattern.Replace(@"[\p{Lu}", "\u0001").Replace(@"\p{Lu}", Lu).Replace("\u0001", @"[\p{Lu}\p{Ll}\p{Lt}"),   // inside a class: no nested brackets
        O, TimeSpan.FromSeconds(1));

    // Architecture
    static readonly Regex ArchX32 = R(@"(?<=^|[^\p{L}\p{Nd}])(X32|X86)(?=\P{Nd}|$)(?:\sEDITION)?");
    static readonly Regex ArchX64 = R(@"(?<=^|[^\p{L}\p{Nd}])(X64|AMD64|X86([\p{Pd}\p{Pc}]64))(?=\P{Nd}|$)(?:\sEDITION)?");
    static readonly Regex ArchArm64 = R(@"(?<=^|[^\p{L}\p{Nd}])(ARM64|AARCH64)(?=\P{Nd}|$)(?:\sEDITION)?");
    static readonly Regex ArchArm = R(@"(?<=^|[^\p{L}\p{Nd}])(ARM32)(?=\P{Nd}|$)(?:\sEDITION)?");
    static readonly Regex Arch32Bit = R(@"(?<=^|[^\p{L}\p{Nd}])(32[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?");
    static readonly Regex Arch64Bit = R(@"(?<=^|[^\p{L}\p{Nd}])(64[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?");
    static readonly Regex Arch32Or64Bit = R(@"(?<=^|[^\p{L}\p{Nd}])((64[\\\/]32|32[\\\/]64)[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?");

    static readonly Regex Locale = R(@"(?<![A-Z])((?:\p{Lu}{2,3}(-(CANS|CYRL|LATN|MONG))?-\p{Lu}{2})(?![A-Z])(?:-VALENCIA)?)");
    static readonly Regex SapPackage = R(@"^(?:[\p{Lu}\p{Nd}]+[\._])+[\p{Lu}\p{Nd}]+(?:-(?:\p{Nd}+\.)+\p{Nd}+)(?:-(?:\p{Lu}{2}(?:_\p{Lu}{2})?|CORE))(?:-(?:\p{Lu}{2}|\p{Nd}{2}))$");
    static readonly Regex KbNumbers = R(@"\((KB\d+)\)");
    static readonly Regex NonLettersAndDigits = R(@"[^\p{L}\p{Nd}]");
    static readonly Regex UriProtocol = R(@"(?<!\p{L})(?:http[s]?|ftp):\/\/");
    static readonly Regex VersionDelimited = R(@"((?<!\p{L})(?:V|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(RC|B|A|R|SP|K)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*");
    static readonly Regex Version = R(@"(FOR\s)?(?<!\p{L})(?:P|V|R|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:RC|B|A|R|V|SP)?\p{Nd}?");
    static readonly Regex VersionLetter = R(@"(?<!\p{L})(?:(?:V|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)\P{L})?\p{Lu}\p{Nd}+(?:[\p{Po}\p{Pd}\p{Pc}]\p{Nd}+)+");
    static readonly Regex NonNestedBracket = R(@"\([^\(\)]*\)|\[[^\[\]]*\]");
    static readonly Regex BracketEnclosed = R(@"(?:\p{Ps}.*\p{Pe}|"".*"")");
    static readonly Regex LeadingSymbols = R(@"^[^\p{L}\p{Nd}]+");
    static readonly Regex TrailingNonLetters = R(@"\P{L}+$");
    static readonly Regex PrefixParens = R(@"^\(.*?\)");
    static readonly Regex EmptyParens = R(@"(\(\s*\)|\[\s*\]|""\s*"")");
    static readonly Regex En = R(@"\sEN\s*$");
    static readonly Regex TrailingSymbols = R(@"[^\p{L}\p{Nd}]+$");
    static readonly Regex FilePath = R(@"((INSTALLED\sAT|IN)\s)?[CDEF]:\\(.+?\\)*[^\s]*\\?");
    static readonly Regex FilePathGhs = R(@"\(CHANGE #\d{1,2} TO [CDEF]:\\(.+?\\)*[^\s]*\\?\)");
    static readonly Regex FilePathParens = R(@"\([CDEF]:\\(.+?\\)*[^\s]*\\?\)");
    static readonly Regex FilePathQuotes = R(@"""[CDEF]:\\(.+?\\)*[^\s]*\\?""");
    static readonly Regex Roblox = R(@"(?<=^ROBLOX\s(PLAYER|STUDIO))(\sFOR\s.*)");
    static readonly Regex Bomgar = R(@"(?<=^BOMGAR\s(JUMP CLIENT|(ACCESS|REPRESENTATIVE) CONSOLE|BUTTON)|^EMBEDDED CALLBACK)(\s.*)");
    static readonly Regex AcronymSeparators = R(@"(?:(?<=^\p{L})|(?<=\P{L}\p{L}))(\.|\/)(?=\p{L}(?:\P{L}|$))");
    static readonly Regex NonLetters = R(@"(?<=^|\s)[^\p{L}]+(?=\s|$)");
    static readonly Regex ProgramNameSplit = R(@"[^\p{L}\p{Nd}\+\&]");
    static readonly Regex PublisherNameSplit = R(@"[^\p{L}\p{Nd}]");

    static readonly Regex[] ProgramNameRegexes =
    [
        Roblox, Bomgar, PrefixParens, EmptyParens, FilePathGhs, FilePathParens, FilePathQuotes, FilePath, VersionLetter,
        VersionDelimited, Version, En, NonNestedBracket, BracketEnclosed, UriProtocol, LeadingSymbols, TrailingSymbols,
    ];

    static readonly Regex[] PublisherNameRegexes =
        [VersionDelimited, Version, NonNestedBracket, BracketEnclosed, UriProtocol, NonLetters, TrailingNonLetters, AcronymSeparators];

    static readonly HashSet<string> Locales = new(
    """
    AF-ZA AM-ET AR-AE AR-BH AR-DZ AR-EG AR-IQ AR-JO AR-KW AR-LB AR-LY AR-MA ARN-CL AR-OM AR-QA AR-SA AR-SY AR-TN AR-YE AS-IN
    BA-RU BE-BY BG-BG BN-BD BN-IN BO-CN BR-FR CA-ES CA-ES-VALENCIA CO-FR CS-CZ CY-GB DA-DK DE-AT DE-CH DE-DE DE-LI DE-LU DSB-DE
    DV-MV EL-GR EN-AU EN-BZ EN-CA EN-GB EN-IE EN-IN EN-JM EN-MY EN-NZ EN-PH EN-SG EN-TT EN-US EN-ZA EN-ZW ES-AR ES-BO ES-CL
    ES-CO ES-CR ES-DO ES-EC ES-ES ES-GT ES-HN ES-MX ES-NI ES-PA ES-PE ES-PR ES-PY ES-SV ES-US ES-UY ES-VE ET-EE EU-ES FA-IR
    FI-FI FIL-PH FO-FO FR-BE FR-CA FR-CH FR-FR FR-LU FR-MC FY-NL GA-IE GD-DB GL-ES GSW-FR GU-IN HE-IL HI-IN HR-BA HR-HR HSB-DE
    HU-HU HY-AM ID-ID IG-NG II-CN IS-IS IT-CH IT-IT JA-JP KA-GE KK-KZ KL-GL KM-KH KN-IN KOK-IN KO-KR KY-KG LB-LU LO-LA LT-LT
    LV-LV MI-NZ MK-MK ML-IN MN-MN MOH-CA MR-IN MS-BN MS-MY MT-MT NB-NO NE-NP NL-BE NL-NL NN-NO NSO-ZA OC-FR OR-IN PA-IN PL-PL
    PRS-AF PS-AF PT-BR PT-PT QUT-GT QUZ-BO QUZ-EC QUZ-PE RM-CH RO-RO RU-RU RW-RW SAH-RU SA-IN SE-FI SE-NO SE-SE SI-LK SK-SK
    SL-SI SMA-NO SMA-SE SMJ-NO SMJ-SE SMN-FI SMS-FI SQ-AL SV-FI SV-SE SW-KE SYR-SY TA-IN TE-IN TH-TH TK-TM TN-ZA TR-TR TT-RU
    UG-CN UK-UA UR-PK VI-VN WO-SN XH-ZA YO-NG ZH-CN ZH-HK ZH-MO ZH-SG ZH-TW ZU-ZA AZ-CYRL-AZ AZ-LATN-AZ BS-CYRL-BA BS-LATN-BA
    HA-LATN-NG IU-CANS-CA IU-LATN-CA MN-MONG-CN SR-CYRL-BA SR-CYRL-CS SR-CYRL-ME SR-CYRL-RS SR-LATN-BA SR-LATN-CS SR-LATN-ME
    SR-LATN-RS TG-CYRL-TJ TZM-LATN-DZ UZ-CYRL-UZ UZ-LATN-UZ
    """.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Select(Fold), StringComparer.Ordinal);

    static readonly HashSet<string> LegalEntitySuffixes = new(new[]
    {
        "AB", "AD", "AG", "APS", "AS", "ASA", "BV", "CO", "CV", "DOO", "eV", "GES", "GESMBH", "GMBH", "INC", "KG", "KS", "PS", "LLC",
        "LP", "LTD", "LTDA", "MBH", "NV", "PLC", "SL", "PTY", "PVT", "SA", "SARL", "SC", "SCA", "SP", "SPA", "SRL", "SRO",
        "COMPANY", "CORP", "CORPORATION", "HOLDING", "HOLDINGS", "INCORPORATED", "LIMITED", "SUBSIDIARY",
    }.Select(Fold), StringComparer.Ordinal);

    static string Fold(string s) => s.ToLowerInvariant();

    static string Prepare(string? value)
    {
        var s = (value ?? "").Normalize(NormalizationForm.FormKC).Trim();
        var at = s.Length > 3 ? s.IndexOf("@@", 3, StringComparison.Ordinal) : -1;
        return at >= 0 ? s[..at] : s;
    }

    static bool Unwrap(ref string v)
    {
        if (v.Length < 2) return false;
        bool unwrap = (v[0] == '"' && v[^1] == '"') || (v[0] == '(' && v[^1] == ')');
        if (unwrap) v = v[1..^1];
        return unwrap;
    }

    static bool Remove(Regex re, ref string input)
    {
        var output = re.Replace(input, "");
        bool changed = output != input;
        input = output;
        return changed;
    }

    static bool RemoveAll(Regex[] regexes, ref string value)
    {
        bool any = false;
        foreach (var re in regexes) any = Remove(re, ref value) || any;
        return any;
    }

    static string? RemoveArchitecture(ref string value)
    {
        if (Remove(Arch32Or64Bit, ref value)) return null;                       // both in one installer: unknown
        if (Remove(ArchX64, ref value) || Remove(Arch64Bit, ref value)) return "X64";
        if (Remove(ArchX32, ref value) || Remove(Arch32Bit, ref value)) return "X86";
        if (Remove(ArchArm64, ref value)) return "Arm64";
        if (Remove(ArchArm, ref value)) return "Arm";
        return null;
    }

    static string RemoveLocale(ref string value)
    {
        bool found = false;
        string result = "";
        value = Locale.Replace(value, m =>
        {
            var folded = Fold(m.Value);
            if (!Locales.Contains(folded)) return m.Value;                       // not a locale we know: keep the text
            if (!found) { result = folded; found = true; }
            else if (result.Length > 0 && result != folded)
            {
                var a = result[..result.IndexOf('-')];
                var b = folded[..folded.IndexOf('-')];
                result = a == b ? a : "";
            }
            return "";
        });
        return result;
    }

    /// <summary>
    /// winget's Split: every piece between and including separators, minus whitespace pieces and legal suffixes (never the
    /// first word). For publishers it stops at the first legal suffix ("Hewlett-Packard Development Company, L.P.").
    /// </summary>
    static List<string> Split(Regex re, string value, bool stopOnExclusion)
    {
        var result = new List<string>();
        int pos = 0;
        IEnumerable<string> Pieces()
        {
            foreach (Match m in re.Matches(value))
            {
                if (m.Index > pos) yield return value[pos..m.Index];
                yield return m.Value;
                pos = m.Index + m.Length;
            }
            if (pos < value.Length) yield return value[pos..];
        }
        foreach (var text in Pieces())
        {
            if (string.IsNullOrWhiteSpace(text)) continue;
            if (result.Count > 0 && LegalEntitySuffixes.Contains(Fold(text)))
            {
                if (stopOnExclusion) break;
                continue;
            }
            result.Add(text);
        }
        return result;
    }

    public static Result Name(string? name)
    {
        var s = Prepare(name);
        while (Unwrap(ref s)) { }
        if (SapPackage.IsMatch(s)) return new Result(s, null, "");
        var arch = RemoveArchitecture(ref s);
        var locale = RemoveLocale(ref s);
        s = KbNumbers.Replace(s, "$1");
        while (RemoveAll(ProgramNameRegexes, ref s)) { }
        s = NonLettersAndDigits.Replace(string.Concat(Split(ProgramNameSplit, s, false)), "");
        return new Result(s, arch, locale);
    }

    public static string Publisher(string? publisher)
    {
        var s = Prepare(publisher);
        while (Unwrap(ref s)) { }
        while (RemoveAll(PublisherNameRegexes, ref s)) { }
        return NonLettersAndDigits.Replace(string.Concat(Split(PublisherNameSplit, s, true)), "");
    }
}
