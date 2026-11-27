using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Persistence;

/// <summary>
/// Startup programs and other autostart entries (registry, scheduled tasks, files, WMI), each scored by
/// <see cref="PersistenceRules"/>. Read-only; bad data becomes warnings, never exceptions.
/// </summary>
public sealed class PersistenceCollector : ICollector
{
    public const string Kind = "persistence";
    public string Name => "Programs that start automatically";

    public CollectorOutput Run(CollectorContext context, CancellationToken ct)
    {
        var notes = new List<string>();
        var entries = new List<PersistenceEntry>();
        var status = CollectorStatus.Ok;
        int warningsBefore = context.Warnings.Count;

        bool Gather(string what, Func<IReadOnlyList<PersistenceEntry>> read)
        {
            context.Progress?.Report($"Checking {what}");
            try { entries.AddRange(read()); return true; }
            catch (OperationCanceledException) { return false; }
            catch (Exception e)
            {
                context.Warnings.Add($"Could not check {what}: {e.Message}");
                status = CollectorStatus.Partial;
                return true;
            }
        }

        bool ok = Gather("startup entries in the registry", () => RegistryPersistence.Read(context.Source, context.Warnings, ct))
            && Gather("scheduled tasks", () => TaskPersistence.Read(context.Source, context.Warnings, ct))
            && Gather("startup folders and profiles", () => FilePersistence.Read(context.Source, context.Wmi, context.Warnings, ct));

        var items = new Dictionary<string, PersistenceItem>(StringComparer.OrdinalIgnoreCase);
        var cache = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
        context.Progress?.Report("Checking signatures of startup programs");
        foreach (var e in entries)
        {
            if (!ok || ct.IsCancellationRequested) { ok = false; break; }
            try
            {
                var item = Evaluate(e, context.Source, context.Signatures, cache, context.Warnings);
                items.TryAdd(item.ItemKey, item);
            }
            catch (Exception x) when (x is not OperationCanceledException)
            {
                context.Warnings.Add($"An autostart entry could not be checked ({e.Location}): {x.Message}");
                status = CollectorStatus.Partial;
            }
        }

        var list = items.Values.OrderByDescending(i => i.Severity).ThenBy(i => i.Location, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList<IScanItem>();
        var bySeverity = items.Values.GroupBy(i => i.Severity).ToDictionary(g => g.Key, g => g.Count());
        notes.Add($"{items.Count} autostart entries: " + string.Join(", ",
            Enum.GetValues<Severity>().Reverse().Select(s => $"{s} {bySeverity.GetValueOrDefault(s)}")) + ". Hidden entries are normal Windows parts.");
        if (context.Warnings.Count > warningsBefore && status == CollectorStatus.Ok) status = CollectorStatus.Partial;
        if (!ok) status = CollectorStatus.Cancelled;
        return new CollectorOutput(Kind, list, notes, status);
    }

    /// <summary>Parses, maps, signature-checks and scores one entry.</summary>
    public static PersistenceItem Evaluate(PersistenceEntry e, ISystemSource source, ISignatureChecker signatures,
        IDictionary<string, SignatureInfo>? cache = null, IList<string>? warnings = null)
    {
        var env = PersistencePaths.UserEnv(source, e.User);
        bool Exists(string p) => PersistencePaths.FileExists(source, p, e.User);
        var parsed = CommandLine.Parse(e.Command, Exists);

        string? payload = e.NoFile ? null
            : e.Payload is { } explicitPayload ? CommandLine.ResolveBare(explicitPayload, Exists)
            : parsed.Payload;
        bool isUrl = e.Payload is null && parsed.PayloadIsUrl;
        string? expanded = payload is null ? null : SourcePaths.Expand(payload.Trim().Trim('"'), source.OriginalSystemDrive, env);

        var sig = new SignatureInfo(SignatureStatus.NotChecked, null, false);
        if (expanded is not null && !isUrl)
        {
            var mapped = PersistencePaths.MapFile(source, expanded, e.User);
            if (mapped is not null)
            {
                if (cache is null || !cache.TryGetValue(mapped, out var cached))
                {
                    try { cached = signatures.Check(mapped); }
                    catch (Exception x) when (x is not OperationCanceledException)
                    {
                        warnings?.Add($"The signature of a startup program could not be checked: {x.Message}");
                        cached = new SignatureInfo(SignatureStatus.NotChecked, null, false);
                    }
                    cache?.TryAdd(mapped, cached);
                }
                sig = cached;
            }
        }

        var r = PersistenceRules.Score(new RuleInput(e, parsed, expanded, sig));
        var image = parsed.Image is null ? null : SourcePaths.Expand(parsed.Image, source.OriginalSystemDrive, env);
        return new PersistenceItem(e.Location, e.Name, e.Command, image, expanded, sig.Signer, sig.Status, r.Severity, r.RuleId, r.Reason, r.Disabled, e.LastWrite);
    }
}
