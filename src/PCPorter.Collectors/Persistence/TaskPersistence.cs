using System.Buffers.Binary;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

public enum TaskActionKind { Exec, ComHandler }

public sealed record TaskAction(TaskActionKind Kind, string? Command, string? Arguments, string? WorkingDirectory, string? ClassId, string? Data);

public sealed record TaskDefinition(bool Enabled, IReadOnlyList<TaskAction> Actions, string? Author, string? Uri);

/// <summary>
/// Scheduled tasks (plan Task 7c): every task file under Windows\System32\Tasks, including the \Microsoft\ tree (malware
/// hides there), cross-checked against the TaskCache registry for tasks that have no file or no security descriptor.
/// </summary>
public static class TaskPersistence
{
    public static readonly XNamespace Ns = "http://schemas.microsoft.com/windowstask/2004/02/mit/task";
    const string TaskCache = @"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
    const long MaxTaskFile = 4 * 1024 * 1024;

    sealed record TreeEntry(string Path, string? Id, bool HasSd, DateTimeOffset? LastWrite);

    public static IReadOnlyList<PersistenceEntry> Read(ISystemSource source, IList<string> warnings, CancellationToken ct = default)
    {
        var list = new List<PersistenceEntry>();
        IRegKey? software = null;
        try { software = source.OpenHive(Hive.Software); }
        catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"Could not open the SOFTWARE hive for scheduled tasks: {e.Message}"); }
        var cache = software?.Open(TaskCache);
        var tree = new Dictionary<string, TreeEntry>(StringComparer.OrdinalIgnoreCase);
        try { if (cache?.Open("Tree") is { } t) WalkTree(t, "", tree); }
        catch (Exception e) when (e is not OperationCanceledException) { warnings.Add($"Could not read the task list in the registry: {e.Message}"); }
        var classes = software?.Open(@"Classes\CLSID");

        var tasksDir = source.MapPath(@"%SystemRoot%\System32\Tasks");
        bool rootReadable = tasksDir is not null && CanList(tasksDir);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (rootReadable)
        {
            foreach (var file in SourceFiles.Files(tasksDir!, "*", recursive: true))
            {
                ct.ThrowIfCancellationRequested();
                var taskPath = "\\" + Path.GetRelativePath(tasksDir!, file);
                try
                {
                    var info = new FileInfo(file);
                    if (info.Length > MaxTaskFile) { warnings.Add($"Skipped an unusually large task file ({info.Length / 1024} KB)."); continue; }
                    TaskDefinition def;
                    using (var fs = SourceFiles.OpenRead(file)) def = ParseXml(fs);
                    seen.Add(taskPath);
                    tree.TryGetValue(taskPath, out var te);
                    var hidden = te is { HasSd: false };
                    list.AddRange(ToEntries(taskPath, def, classes, hidden, info.LastWriteTimeUtc));
                }
                catch (Exception e) when (e is XmlException or IOException or UnauthorizedAccessException or InvalidDataException)
                {
                    warnings.Add($"A scheduled task file could not be read ({taskPath}): {e.Message}");
                }
            }
        }
        else warnings.Add("The scheduled task folder could not be read (run as administrator to include task files); tasks were read from the registry instead.");

        // Registry-only tasks (no file) and tasks without a security descriptor (hidden from Task Scheduler).
        var byId = cache?.Open("Tasks");
        foreach (var te in tree.Values)
        {
            ct.ThrowIfCancellationRequested();
            if (seen.Contains(te.Path)) continue;
            try
            {
                bool fileMissing = false;
                if (rootReadable)
                {
                    var expected = Path.Combine(tasksDir!, te.Path.TrimStart('\\'));
                    var parent = Path.GetDirectoryName(expected)!;
                    bool parentListable = Directory.Exists(parent) ? CanList(parent) : true;
                    fileMissing = parentListable && !File.Exists(expected);
                }
                var hidden = fileMissing || !te.HasSd;
                var actions = te.Id is not null && byId?.Open(te.Id)?.GetBytes("Actions") is { } blob ? ParseActionsBlob(blob) : [];
                var reason = fileMissing ? "There is no task file for it." : !te.HasSd ? "Its security information was removed." : null;
                var entries = ToEntries(te.Path, new TaskDefinition(true, actions, null, te.Path), classes, hidden, te.LastWrite?.UtcDateTime).ToList();
                if (entries.Count == 0)
                    entries.Add(new PersistenceEntry(Folder(te.Path), Leaf(te.Path), "", EntryKind.Task) { TaskHidden = hidden, NoFile = true, LastWrite = te.LastWrite });
                list.AddRange(entries.Select(x => x with { Note = Join(x.Note, reason), NoFile = x.NoFile || (x.Command.Length == 0) }));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
            {
                warnings.Add($"A task in the registry could not be checked ({te.Path}): {e.Message}");
            }
        }
        return list;
    }

    static string? Join(string? a, string? b) => a is null ? b : b is null ? a : a + " " + b;

    static string Folder(string taskPath)
    {
        var i = taskPath.LastIndexOf('\\');
        return "Task Scheduler" + (i > 0 ? taskPath[..i] : "");
    }

    static string Leaf(string taskPath) => taskPath[(taskPath.LastIndexOf('\\') + 1)..];

    static bool CanList(string dir)
    {
        try { using var e = Directory.EnumerateFileSystemEntries(dir).GetEnumerator(); e.MoveNext(); return true; }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return false; }
    }

    static void WalkTree(IRegKey key, string path, Dictionary<string, TreeEntry> into)
    {
        foreach (var k in key.SubKeys)
        {
            var p = path + "\\" + k.Name;
            var id = k.GetString("Id");
            if (id is not null)
            {
                var sd = k.GetRaw("SD");
                into[p] = new TreeEntry(p, id, sd is { Raw.Length: > 0 }, k.LastWrite);
            }
            WalkTree(k, p, into);
        }
    }

    static IEnumerable<PersistenceEntry> ToEntries(string taskPath, TaskDefinition def, IRegKey? classes, bool hidden, DateTime? lastWriteUtc)
    {
        var lw = lastWriteUtc is { } d ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc)) : (DateTimeOffset?)null;
        int n = 0;
        foreach (var a in def.Actions)
        {
            n++;
            var name = Leaf(taskPath) + (def.Actions.Count > 1 ? $" (action {n})" : "");
            if (a.Kind == TaskActionKind.Exec)
            {
                if (string.IsNullOrWhiteSpace(a.Command)) continue;
                var cmd = a.Command.Trim();
                if (!cmd.StartsWith('"') && cmd.Contains(' ')) cmd = "\"" + cmd + "\"";   // Task Scheduler treats Command as one path
                if (!string.IsNullOrWhiteSpace(a.Arguments)) cmd += " " + a.Arguments.Trim();
                yield return new PersistenceEntry(Folder(taskPath), name, cmd, EntryKind.Task) { Disabled = !def.Enabled, TaskHidden = hidden, LastWrite = lw };
            }
            else
            {
                var clsid = a.ClassId?.Trim() ?? "";
                var server = ResolveClsid(classes, clsid);
                yield return new PersistenceEntry(Folder(taskPath), name, server ?? clsid, EntryKind.Task)
                {
                    Disabled = !def.Enabled, TaskHidden = hidden, LastWrite = lw, NoFile = server is null,
                    Note = server is null ? $"It runs the COM handler {clsid}, which is not registered." : $"It runs the COM handler {clsid}.",
                };
            }
        }
    }

    public static string? ResolveClsid(IRegKey? classesClsid, string clsid)
    {
        if (classesClsid is null || clsid.Length == 0) return null;
        var id = clsid.StartsWith('{') ? clsid : "{" + clsid + "}";
        var v = classesClsid.Open(id)?.Open("InprocServer32")?.GetString("");
        return string.IsNullOrWhiteSpace(v) ? null : v;
    }

    /// <summary>Parses a task XML file (UTF-16 LE with BOM as Windows writes them; any encoding with a BOM/declaration works).</summary>
    public static TaskDefinition ParseXml(Stream stream)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true };
        using var reader = XmlReader.Create(stream, settings);
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new InvalidDataException("Empty task file.");
        // Namespace-aware, but tolerant of files written without the task namespace.
        XElement? El(XElement? parent, string name) => parent?.Element(Ns + name) ?? parent?.Element(name);

        var enabledText = El(El(root, "Settings"), "Enabled")?.Value.Trim();
        bool enabled = !string.Equals(enabledText, "false", StringComparison.OrdinalIgnoreCase) && enabledText != "0";
        var actionsEl = El(root, "Actions");
        var actions = new List<TaskAction>();
        if (actionsEl is not null)
            foreach (var a in actionsEl.Elements())
            {
                if (a.Name.LocalName == "Exec")
                    actions.Add(new TaskAction(TaskActionKind.Exec, El(a, "Command")?.Value, El(a, "Arguments")?.Value, El(a, "WorkingDirectory")?.Value, null, null));
                else if (a.Name.LocalName == "ComHandler")
                    actions.Add(new TaskAction(TaskActionKind.ComHandler, null, null, null, El(a, "ClassId")?.Value, El(a, "Data")?.Value));
            }
        var reg = El(root, "RegistrationInfo");
        return new TaskDefinition(enabled, actions, El(reg, "Author")?.Value, El(reg, "URI")?.Value);
    }

    /// <summary>
    /// Best-effort decoder for TaskCache\Tasks\{id}\Actions: uint16 version, length-prefixed UTF-16 context, then actions
    /// (0x6666 exec: id, command, arguments, working dir [, uint16 flags from version 3]; 0x7777 COM: id, CLSID, data).
    /// </summary>
    public static IReadOnlyList<TaskAction> ParseActionsBlob(byte[] blob)
    {
        var list = new List<TaskAction>();
        try
        {
            int pos = 0;
            var version = ReadU16(blob, ref pos);
            _ = ReadStr(blob, ref pos);          // context ("Author" / principal id)
            while (pos + 2 <= blob.Length)
            {
                var magic = ReadU16(blob, ref pos);
                if (magic == 0x6666)
                {
                    _ = ReadStr(blob, ref pos);
                    var cmd = ReadStr(blob, ref pos);
                    var args = ReadStr(blob, ref pos);
                    var wd = ReadStr(blob, ref pos);
                    if (version >= 3 && pos + 2 <= blob.Length) pos += 2;
                    list.Add(new TaskAction(TaskActionKind.Exec, cmd, args, wd, null, null));
                }
                else if (magic == 0x7777)
                {
                    _ = ReadStr(blob, ref pos);
                    if (pos + 16 > blob.Length) break;
                    var clsid = new Guid(blob.AsSpan(pos, 16)).ToString("B").ToUpperInvariant();
                    pos += 16;
                    var data = ReadStr(blob, ref pos);
                    list.Add(new TaskAction(TaskActionKind.ComHandler, null, null, null, clsid, data));
                }
                else break;   // e-mail / message actions or unknown layout: stop
            }
        }
        catch (InvalidDataException) { }
        return list;
    }

    static ushort ReadU16(byte[] b, ref int pos)
    {
        if (pos + 2 > b.Length) throw new InvalidDataException();
        var v = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(pos));
        pos += 2;
        return v;
    }

    static string ReadStr(byte[] b, ref int pos)
    {
        if (pos + 4 > b.Length) throw new InvalidDataException();
        var len = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(pos));
        pos += 4;
        if (len < 0 || len > b.Length - pos) throw new InvalidDataException();
        var s = Encoding.Unicode.GetString(b, pos, len & ~1);
        pos += len;
        return s.TrimEnd('\0');
    }
}
