namespace PCPorter.Core;

/// <summary>
/// The drive or folder the person asked PCPorter to scan cannot be used (it is the running Windows, holds no Windows
/// installation, or cannot be read). The message is written for the person and is safe to show as is.
/// Callers map this (and <see cref="Case.CaseLocationRejectedException"/>) to "Can't start" / exit code 3.
/// It derives from <see cref="InvalidOperationException"/> only so older catch blocks keep working.
/// </summary>
public sealed class SourceRejectedException(string message) : InvalidOperationException(message);
