using System.Security.Principal;
using PCPorter.Collectors.Sources;
using Xunit;

namespace PCPorter.TestKit;

/// <summary>Runs only in an elevated test session. Mark with [Trait("Category","Admin")] and run elevated with --filter Category=Admin.</summary>
public sealed class AdminFactAttribute : FactAttribute
{
    public static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    public AdminFactAttribute() { if (!IsAdmin) Skip = "Requires an elevated (administrator) test run."; }
}

/// <summary>An in-memory PC: hives from RegSpecs, files from a temp folder.</summary>
public sealed class FakeSystemSource(string readRoot, RegSpec? software = null, RegSpec? system = null,
    IReadOnlyDictionary<string, RegSpec>? userHives = null, IReadOnlyList<UserProfile>? users = null, bool live = false) : ISystemSource
{
    public bool IsLive => live;
    public string ReadRoot { get; } = readRoot.EndsWith('\\') ? readRoot : readRoot + "\\";
    public string OriginalSystemDrive => "C:";
    public IReadOnlyList<UserProfile> Users => users ?? [];
    public IReadOnlyList<string> Notes => [];
    public string? MapPath(string pathFromScannedPc) => SourcePaths.Map(pathFromScannedPc, OriginalSystemDrive, ReadRoot);
    public string? CurrentControlSet() => SourcePaths.ControlSetName(system?.ToFake());

    public IRegKey? OpenHive(Hive hive, UserProfile? user = null) => hive switch
    {
        Hive.Software => software?.ToFake(),
        Hive.System => system?.ToFake(),
        Hive.NtUser when user is not null && userHives?.TryGetValue(user.Sid, out var u) == true => u.ToFake(),
        Hive.UsrClass when user is not null && userHives?.TryGetValue(user.Sid + "_Classes", out var c) == true => c.ToFake(),
        _ => null,
    };

    public void Dispose() { }
}

/// <summary>Answers WMI queries from canned rows keyed by (namespace, class name found in the query).</summary>
public sealed class FakeWmiClient : IWmiClient
{
    readonly List<(string Ns, string Class, WmiResult Result)> _answers = [];
    public List<string> Queries { get; } = [];

    public FakeWmiClient Add(string ns, string cls, params Dictionary<string, object?>[] rows)
    {
        _answers.Add((ns, cls, new WmiResult(WmiOutcome.Ok, rows)));
        return this;
    }

    public FakeWmiClient Fail(string ns, string cls, WmiOutcome outcome)
    {
        _answers.Add((ns, cls, WmiResult.Fail(outcome, outcome.ToString())));
        return this;
    }

    public WmiResult Query(string ns, string wql, TimeSpan? timeout = null)
    {
        Queries.Add($"{ns}|{wql}");
        // Whole-word match, so "Win32_Volume" never answers a query for "Win32_VolumeQuota"
        // (a registered key may also be a longer query fragment, e.g. "SoftwareLicensingProduct WHERE").
        foreach (var (n, c, r) in _answers)
            if (string.Equals(n, ns, StringComparison.OrdinalIgnoreCase) &&
                System.Text.RegularExpressions.Regex.IsMatch(wql, @"(?<!\w)" + System.Text.RegularExpressions.Regex.Escape(c) + @"(?!\w)",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return r;
        return WmiResult.Fail(WmiOutcome.InvalidNamespace, "not faked");
    }
}

public sealed class FakeProcessRunner(Func<string, IReadOnlyList<string>, ProcessResult> handler) : IProcessRunner
{
    public List<string> Started { get; } = [];
    public ProcessResult Run(string system32Exe, IReadOnlyList<string> args, TimeSpan timeout)
    {
        Started.Add(system32Exe + " " + string.Join(' ', args));
        return handler(system32Exe, args);
    }
}
