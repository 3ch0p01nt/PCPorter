namespace PCPorter.Core.Case;

/// <summary>How strong the evidence is: the item existed, or it actually ran / was used.</summary>
public enum Confidence { Existed = 0, Ran = 1 }

/// <summary>One normalized evidence row. Every collector produces these.</summary>
public sealed record Artifact(
    DateTimeOffset? TsUtc, string Category, string Source, string ArtifactName,
    string? User, string Action, string Subject, string? Detail, Confidence Confidence);
