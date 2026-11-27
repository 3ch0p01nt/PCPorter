namespace PCPorter.Collectors.Security;

public enum WscState { Off, On, Snoozed, Expired, Unknown }

public sealed record ProductStatus(WscState State, bool UpToDate, bool IsMicrosoft);

/// <summary>Decodes the Windows Security Center <c>productState</c> number.</summary>
public static class ProductState
{
    // Undocumented community layout of WSC productState: 0x00F000 state, 0x000F00 owner (0x100 = Windows), 0x0000F0 signatures (0x00 = up to date)
    public static ProductStatus Decode(uint s) => new(
        ((s >> 12) & 0xF) switch { 0 => WscState.Off, 1 => WscState.On, 2 => WscState.Snoozed, 3 => WscState.Expired, _ => WscState.Unknown },
        (s & 0xF0) == 0, (s & 0x0F00) == 0x100);

    /// <summary>Plain words for the report.</summary>
    public static string Describe(ProductStatus p) => p.State switch
    {
        WscState.On => p.UpToDate ? "on" : "on, but out of date",
        WscState.Off => "turned off",
        WscState.Snoozed => "snoozed",
        WscState.Expired => "license expired",
        _ => "unknown",
    };
}
