using System.Text;

namespace PCPorter.Collectors.Apps;

/// <summary>A node of Valve's KeyValues text format (libraryfolders.vdf, appmanifest_*.acf). Keys are case-insensitive.</summary>
public sealed class VdfNode
{
    public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, VdfNode> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? this[string key] => Values.TryGetValue(key, out var v) ? v : null;
    public VdfNode? Child(string key) => Children.TryGetValue(key, out var c) ? c : null;
}

/// <summary>Tiny tolerant KeyValues parser: quoted or bare tokens, nested braces, // comments, [$CONDITION] tags ignored.
/// Malformed input never throws; whatever was parsed before the problem is returned.</summary>
public static class Vdf
{
    public static VdfNode Parse(string text)
    {
        var root = new VdfNode();
        var stack = new Stack<VdfNode>();
        stack.Push(root);
        string? pendingKey = null;
        foreach (var (tok, quoted) in Tokens(text))
        {
            if (!quoted && tok.StartsWith('[') && tok.EndsWith(']')) continue;        // conditional tag
            if (!quoted && tok == "{")
            {
                var child = new VdfNode();
                stack.Peek().Children[pendingKey ?? ""] = child;
                stack.Push(child);
                pendingKey = null;
            }
            else if (!quoted && tok == "}")
            {
                pendingKey = null;
                if (stack.Count > 1) stack.Pop();
            }
            else if (pendingKey is null) pendingKey = tok;
            else { stack.Peek().Values[pendingKey] = tok; pendingKey = null; }
        }
        return root;
    }

    static IEnumerable<(string Token, bool Quoted)> Tokens(string s)
    {
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') { while (i < s.Length && s[i] != '\n') i++; continue; }
            if (c is '{' or '}') { i++; yield return (c.ToString(), false); continue; }
            if (c == '"')
            {
                var sb = new StringBuilder();
                i++;
                while (i < s.Length && s[i] != '"')
                {
                    if (s[i] == '\\' && i + 1 < s.Length)
                    {
                        char n = s[i + 1];
                        sb.Append(n switch { 'n' => '\n', 't' => '\t', '\\' => '\\', '"' => '"', _ => n });
                        i += 2;
                        continue;
                    }
                    sb.Append(s[i++]);
                }
                i++;                                                               // closing quote (or end of text)
                yield return (sb.ToString(), true);
                continue;
            }
            int start = i;
            while (i < s.Length && !char.IsWhiteSpace(s[i]) && s[i] is not ('{' or '}' or '"')) i++;
            yield return (s[start..i], false);
        }
    }
}
