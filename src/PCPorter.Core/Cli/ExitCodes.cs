namespace PCPorter.Core.Cli;

/// <summary>Process exit codes for unattended runs. Documented for scripts and scheduled tasks.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int Partial = 1;
    public const int Failed = 2;
    public const int BadArguments = 3;
    public const int NotElevated = 4;
    /// <summary>The scan finished but found items at or above the --fail-on level.</summary>
    public const int FindingsFound = 5;
    /// <summary>Stopped by Ctrl+C before the end; the case holds what was done so far.</summary>
    public const int Cancelled = 6;
}
