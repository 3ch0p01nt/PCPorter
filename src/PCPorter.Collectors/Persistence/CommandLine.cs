using System.Text;

namespace PCPorter.Collectors.Persistence;

/// <param name="Raw">The command as stored.</param>
/// <param name="Image">The program that starts (scanned-PC path; env vars kept; bare system names resolved to %SystemRoot%\System32).</param>
/// <param name="Arguments">Everything after the image.</param>
/// <param name="Quoted">The image was in quotes.</param>
/// <param name="UnquotedPath">The image is unquoted and its path has spaces (or could not be told apart from its arguments).</param>
/// <param name="Payload">What actually runs: the DLL for rundll32/regsvr32, the script for wscript/cscript/mshta/powershell, the
/// first command for cmd /c, else the image. Null when the payload is inline code.</param>
/// <param name="Host">Lower-case host name (rundll32, powershell...) when the payload was taken from a host's arguments.</param>
/// <param name="PayloadIsUrl">The payload is a URL (mshta http://..., wscript http://...).</param>
/// <param name="Inline">The host runs inline code (powershell -Command, mshta vbscript:, rundll32 javascript:).</param>
public sealed record ParsedCommand(
    string Raw, string? Image, string Arguments, bool Quoted, bool UnquotedPath,
    string? Payload, string? Host, bool PayloadIsUrl, bool Inline);

/// <summary>Splits Windows command lines into image, arguments and effective payload (pure; file checks via a seam).</summary>
public static class CommandLine
{
    static readonly string[] ExecutableExtensions =
        [".exe", ".com", ".bat", ".cmd", ".dll", ".scr", ".cpl", ".sys", ".ocx", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msc", ".lnk"];

    /// <param name="fileExists">Is this scanned-PC path an existing file? Used to resolve unquoted paths with spaces.</param>
    public static ParsedCommand Parse(string? command, Func<string, bool>? fileExists = null) => Parse(command, fileExists, 0);

    static ParsedCommand Parse(string? command, Func<string, bool>? fileExists, int depth)
    {
        var raw = command ?? "";
        var s = raw.Trim().Replace('\0', ' ').Trim();
        if (s.Length == 0) return new(raw, null, "", false, false, null, null, false, false);

        string image, args;
        bool quoted = false, unquoted = false;
        if (s[0] == '"')
        {
            quoted = true;
            int end = s.IndexOf('"', 1);
            if (end < 0) { image = s[1..]; args = ""; }
            else { image = s[1..end]; args = s[(end + 1)..].Trim(); }
        }
        else
        {
            var cut = ImageLength(s, fileExists, out bool guessed);
            image = s[..cut];
            args = s[cut..].Trim();
            unquoted = image.Contains(' ') || (guessed && args.Length > 0 && LooksLikePathContinuation(args));
        }

        image = ResolveBare(image.Trim(), fileExists);
        var host = HostName(image);
        string? payload = image;
        bool isUrl = false, inline = false;
        string? hostTag = null;
        if (host is not null && depth < 4)
        {
            hostTag = host;
            (payload, isUrl, inline) = HostPayload(host, args, fileExists, depth);
            if (payload is not null && !isUrl) payload = ResolveBare(payload, fileExists);
        }
        return new(raw, image, args, quoted, unquoted, payload, hostTag, isUrl, inline);
    }

    /// <summary>Length of the image part of an unquoted command line.</summary>
    static int ImageLength(string s, Func<string, bool>? fileExists, out bool guessed)
    {
        guessed = false;
        var cuts = new List<int>();
        for (int i = 0; i < s.Length; i++) if (s[i] == ' ' || s[i] == '\t') cuts.Add(i);
        if (cuts.Count == 0) return s.Length;
        cuts.Add(s.Length);

        // 0. A bare first word ("rundll32", "cscript.exe") is the program; bare names have no spaces.
        var first = s[..cuts[0]];
        if (!first.Contains('\\') && !first.Contains('/') && !first.Contains(':')) return cuts[0];

        // 1. Longest prefix (at a space boundary) that exists on the scanned PC.
        if (fileExists is not null)
            for (int i = cuts.Count - 1; i >= 0; i--)
            {
                var candidate = s[..cuts[i]].TrimEnd();
                if (candidate.Length > 0 && SafeExists(fileExists, candidate)) return cuts[i];
            }
        // 2. Shortest prefix that ends in an executable extension.
        foreach (var c in cuts)
        {
            var candidate = s[..c].TrimEnd();
            if (ExecutableExtensions.Any(e => candidate.EndsWith(e, StringComparison.OrdinalIgnoreCase))) return c;
        }
        // 3. First token.
        guessed = true;
        return cuts[0];
    }

    static bool LooksLikePathContinuation(string args) => args.Contains('\\') && !args.StartsWith('-') && !args.StartsWith('/');

    static bool SafeExists(Func<string, bool> fileExists, string path)
    {
        try { return fileExists(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }

    /// <summary>A bare file name ("rundll32.exe", "shell32.dll") is resolved to %SystemRoot%\System32 (or %SystemRoot% when it exists there).</summary>
    public static string ResolveBare(string path, Func<string, bool>? fileExists = null)
    {
        var p = path.Trim().Trim('"');
        if (p.Length == 0 || p.Contains('\\') || p.Contains('/') || p.Contains(':') || p.StartsWith('%')) return p;
        var name = Path.HasExtension(p) ? p : p + ".exe";
        var sys32 = @"%SystemRoot%\System32\" + name;
        if (fileExists is not null && !SafeExists(fileExists, sys32) && SafeExists(fileExists, @"%SystemRoot%\" + name)) return @"%SystemRoot%\" + name;
        return sys32;
    }

    static string? HostName(string image)
    {
        var name = FileNameOf(image).ToLowerInvariant();
        if (name.EndsWith(".exe", StringComparison.Ordinal)) name = name[..^4];
        return name switch
        {
            "rundll32" or "regsvr32" or "wscript" or "cscript" or "mshta" or "powershell" or "pwsh" or "cmd" => name,
            _ => null,
        };
    }

    static string FileNameOf(string path)
    {
        var i = path.LastIndexOfAny(['\\', '/']);
        return i >= 0 ? path[(i + 1)..] : path;
    }

    static bool IsUrl(string s) => s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    static bool IsInlineScheme(string s) => s.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) || s.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase)
        || s.StartsWith("about:", StringComparison.OrdinalIgnoreCase);

    static (string? Payload, bool Url, bool Inline) HostPayload(string host, string args, Func<string, bool>? fileExists, int depth)
    {
        var tokens = Tokenize(args);
        switch (host)
        {
            case "rundll32":
            {
                if (tokens.Count == 0) return (null, false, false);
                var first = tokens[0];
                if (IsInlineScheme(first) || args.Contains("javascript:", StringComparison.OrdinalIgnoreCase)) return (null, false, true);
                var comma = first.IndexOf(',');
                var dll = comma >= 0 ? first[..comma] : first;
                return (dll.Trim(), false, false);
            }
            case "regsvr32":
            {
                var file = tokens.LastOrDefault(t => !t.StartsWith('/') && !t.StartsWith('-'));
                return file is null ? (null, false, false) : (file, IsUrl(file), false);
            }
            case "wscript" or "cscript":
            {
                var file = tokens.FirstOrDefault(t => !t.StartsWith("//", StringComparison.Ordinal) && !(t.StartsWith('/') && t.Length <= 3) && !t.StartsWith('-'));
                return file is null ? (null, false, false) : (file, IsUrl(file), false);
            }
            case "mshta":
            {
                if (tokens.Count == 0) return (null, false, false);
                var first = tokens[0];
                if (IsInlineScheme(first)) return (null, false, true);
                return (first, IsUrl(first), false);
            }
            case "powershell" or "pwsh":
            {
                for (int i = 0; i < tokens.Count; i++)
                {
                    var t = tokens[i];
                    if (!t.StartsWith('-') && !t.StartsWith('/'))
                    {
                        // First positional argument: a script file for pwsh/powershell, else inline command text.
                        return t.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ? (t, IsUrl(t), false) : (null, false, true);
                    }
                    var sw = t.TrimStart('-', '/').ToLowerInvariant();
                    if (sw.Length >= 1 && "file".StartsWith(sw, StringComparison.Ordinal) && sw != "")
                        return i + 1 < tokens.Count ? (tokens[i + 1], IsUrl(tokens[i + 1]), false) : (null, false, false);
                    if (sw.Length >= 1 && ("command".StartsWith(sw, StringComparison.Ordinal) || "encodedcommand".StartsWith(sw, StringComparison.Ordinal) || sw == "ec"))
                        return (null, false, true);
                    if (TakesValue(sw)) i++;
                }
                return (null, false, false);
            }
            case "cmd":
            {
                var rest = AfterSwitch(args);
                if (rest is null) return (null, false, false);
                rest = FirstCommand(StripCmdQuotes(rest));
                rest = SkipStart(rest);
                if (rest.Length == 0) return (null, false, false);
                var inner = Parse(rest, fileExists, depth + 1);
                if (inner.Inline) return (null, false, true);
                return (inner.Payload ?? inner.Image, inner.PayloadIsUrl, false);
            }
        }
        return (null, false, false);
    }

    static bool TakesValue(string sw) => sw is "executionpolicy" or "ep" or "ex" or "exec" or "windowstyle" or "w" or "win" or "window"
        or "version" or "v" or "configurationname" or "inputformat" or "outputformat" or "of" or "if" or "psconsolefile" or "workingdirectory" or "wd";

    static string? AfterSwitch(string args)
    {
        for (int i = 0; i + 1 < args.Length; i++)
        {
            if (args[i] != '/') continue;
            var c = char.ToLowerInvariant(args[i + 1]);
            if ((c == 'c' || c == 'k') && (i + 2 == args.Length || args[i + 2] == ' ' || args[i + 2] == '"'))
                return args[(i + 2)..].Trim();
        }
        return null;
    }

    static string StripCmdQuotes(string rest)
    {
        // cmd /c ""C:\a b\x.exe" arg" -> "C:\a b\x.exe" arg
        if (rest.StartsWith("\"\"", StringComparison.Ordinal) && rest.EndsWith('"')) return rest[1..^1];
        if (rest.Length > 1 && rest[0] == '"' && rest[^1] == '"' && rest.Count(ch => ch == '"') > 2)
        {
            var inner = rest[1..^1];
            if (inner.Length > 0 && inner[0] != '"' && inner.Contains('"')) return inner;
        }
        return rest;
    }

    static string FirstCommand(string rest)
    {
        bool inQuote = false;
        for (int i = 0; i < rest.Length; i++)
        {
            if (rest[i] == '"') inQuote = !inQuote;
            else if (!inQuote && rest[i] is '&' or '|' or '>' or '<') return rest[..i].Trim();
        }
        return rest.Trim();
    }

    static string SkipStart(string rest)
    {
        if (!rest.StartsWith("start ", StringComparison.OrdinalIgnoreCase) && !rest.StartsWith("start\t", StringComparison.OrdinalIgnoreCase)) return rest;
        var r = rest[6..].TrimStart();
        while (r.StartsWith('/'))
        {
            var sp = r.IndexOf(' ');
            if (sp < 0) return "";
            var sw = r[..sp].ToLowerInvariant();
            r = r[sp..].TrimStart();
            if (sw is "/d" or "/affinity" or "/node" && r.Length > 0) { var sp2 = r.IndexOf(' '); r = sp2 < 0 ? "" : r[sp2..].TrimStart(); }
        }
        // Optional window title: a quoted first token followed by more text.
        if (r.StartsWith('"'))
        {
            int end = r.IndexOf('"', 1);
            if (end > 0 && end + 1 < r.Length && r[(end + 1)..].Trim().Length > 0)
            {
                var title = r[1..end];
                if (!title.Contains('\\') && !ExecutableExtensions.Any(e => title.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                    r = r[(end + 1)..].TrimStart();
            }
        }
        return r;
    }

    /// <summary>Windows-style argument splitting: whitespace separates, quotes group (and are removed).</summary>
    public static List<string> Tokenize(string args)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        bool inQuote = false, any = false;
        foreach (var ch in args)
        {
            if (ch == '"') { inQuote = !inQuote; any = true; continue; }
            if (!inQuote && (ch == ' ' || ch == '\t'))
            {
                if (any || sb.Length > 0) { list.Add(sb.ToString()); sb.Clear(); any = false; }
                continue;
            }
            sb.Append(ch);
        }
        if (any || sb.Length > 0) list.Add(sb.ToString());
        return list;
    }
}
