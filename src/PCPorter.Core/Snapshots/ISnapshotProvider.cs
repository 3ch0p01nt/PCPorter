namespace PCPorter.Core.Snapshots;

/// <summary>A read-only point-in-time copy of a volume. Deleted when disposed.</summary>
public interface ISnapshot : IDisposable
{
    /// <summary>Device path of the snapshot, e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12</summary>
    string DeviceRoot { get; }

    /// <summary>Maps a live path (C:\Users\x\file) to the same file inside the snapshot.</summary>
    string Map(string livePath);
}

public interface ISnapshotProvider
{
    ISnapshot Create(string volumeRoot);
}
