using PCPorter.Collectors.Persistence;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Persistence;

/// <summary>Signature checker answering from a function (receives the MAPPED path).</summary>
public sealed class FakeSignatures(Func<string, SignatureInfo> answer) : ISignatureChecker
{
    public List<string> Checked { get; } = [];
    public SignatureInfo Check(string path) { Checked.Add(path); return answer(path); }

    public static readonly SignatureInfo Microsoft = new(SignatureStatus.Valid, "Microsoft Windows", true);
    public static readonly SignatureInfo Unsigned = new(SignatureStatus.Unsigned, null, false);

    /// <summary>Anything under \Windows\ is Microsoft-signed, everything else unsigned.</summary>
    public static FakeSignatures WindowsIsMicrosoft() =>
        new(p => p.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) ? Microsoft : Unsigned);
}

/// <summary>Wraps a key and records every value name that is read (to prove DefaultPassword is never touched).</summary>
public sealed class RecordingRegKey(IRegKey inner, List<string> reads) : IRegKey
{
    public string Name => inner.Name;
    public DateTimeOffset? LastWrite => inner.LastWrite;
    public IEnumerable<IRegKey> SubKeys => inner.SubKeys.Select(k => (IRegKey)new RecordingRegKey(k, reads));
    public IEnumerable<string> ValueNames { get { reads.Add("<enumerate " + inner.Name + ">"); return inner.ValueNames; } }
    public IRegKey? Open(string relativePath) => inner.Open(relativePath) is { } k ? new RecordingRegKey(k, reads) : null;
    public (RegType Type, byte[] Raw)? GetRaw(string valueName) { reads.Add(inner.Name + ":" + valueName); return inner.GetRaw(valueName); }
}

/// <summary>A FakeSystemSource whose SOFTWARE hive is recorded.</summary>
public sealed class RecordingSource(ISystemSource inner, List<string> reads) : ISystemSource
{
    public bool IsLive => inner.IsLive;
    public string ReadRoot => inner.ReadRoot;
    public string OriginalSystemDrive => inner.OriginalSystemDrive;
    public string? MapPath(string p) => inner.MapPath(p);
    public IRegKey? OpenHive(Hive hive, UserProfile? user = null) => inner.OpenHive(hive, user) is { } k ? new RecordingRegKey(k, reads) : null;
    public string? CurrentControlSet() => inner.CurrentControlSet();
    public IReadOnlyList<UserProfile> Users => inner.Users;
    public IReadOnlyList<string> Notes => inner.Notes;
    public void Dispose() => inner.Dispose();
}

public static class P
{
    public const string BobSid = "S-1-5-21-1-2-3-1001";

    public static CollectorContext Context(ISystemSource source, ISignatureChecker? sigs = null, IWmiClient? wmi = null) =>
        new(source, wmi ?? new FakeWmiClient(), new FakeProcessRunner((_, _) => new ProcessResult(0, "", false)),
            sigs ?? new NoSignatureChecker(), Path.GetTempPath(), new List<string>());

    public static List<PersistenceItem> Items(CollectorOutput o) => o.Items.Cast<PersistenceItem>().ToList();

    public static List<PersistenceItem> Score(ISystemSource source, IEnumerable<PersistenceEntry> entries, ISignatureChecker? sigs = null) =>
        entries.Select(e => PersistenceCollector.Evaluate(e, source, sigs ?? new NoSignatureChecker())).ToList();

    /// <summary>Writes a byte-for-byte Windows-style task file: UTF-16 LE with BOM.</summary>
    public static void WriteTask(string tasksRoot, string taskPath, string actionsXml, bool enabled = true) =>
        TaskXml.Write(tasksRoot, taskPath, actionsXml, enabled);

    public static string Exec(string command, string? args = null) => TaskXml.Exec(command, args);
}
