using System.Runtime.InteropServices;
using PCPorter.Collectors.Sources;

namespace PCPorter.TestKit;

/// <summary>
/// Writes a REAL registry hive file from a <see cref="RegSpec"/> using Windows' Offline Registry Library (offreg.dll,
/// present in System32). No admin rights, no live registry changes.
/// </summary>
public static class OffregHiveBuilder
{
    public static void Save(RegSpec spec, string path)
    {
        Check(ORCreateHive(out var hive), "ORCreateHive");
        try
        {
            Write(hive, spec);
            if (File.Exists(path)) File.Delete(path);
            Check(ORSaveHive(hive, path, 10, 0), "ORSaveHive");
        }
        finally { ORCloseHive(hive); }
    }

    static void Write(IntPtr key, RegSpec spec)
    {
        foreach (var (name, (type, raw)) in spec.Values)
            Check(ORSetValue(key, name.Length == 0 ? null : name, RegSpec.Win32Type(type), raw, (uint)raw.Length), "ORSetValue " + name);
        foreach (var child in spec.Keys.Values)
        {
            Check(ORCreateKey(key, child.Name, null, 0, IntPtr.Zero, out var sub, out _), "ORCreateKey " + child.Name);
            try { Write(sub, child); } finally { ORCloseKey(sub); }
        }
    }

    static void Check(int rc, string what) { if (rc != 0) throw new InvalidOperationException($"{what} failed with {rc}"); }

    const string Dll = "offreg.dll";
    [DllImport(Dll, CharSet = CharSet.Unicode)] static extern int ORCreateHive(out IntPtr hive);
    [DllImport(Dll, CharSet = CharSet.Unicode)] static extern int ORCloseHive(IntPtr hive);
    [DllImport(Dll, CharSet = CharSet.Unicode)] static extern int ORSaveHive(IntPtr hive, string path, uint osMajor, uint osMinor);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    static extern int ORCreateKey(IntPtr key, string subKey, string? cls, uint options, IntPtr securityDescriptor, out IntPtr result, out uint disposition);
    [DllImport(Dll, CharSet = CharSet.Unicode)] static extern int ORCloseKey(IntPtr key);
    [DllImport(Dll, CharSet = CharSet.Unicode)] static extern int ORSetValue(IntPtr key, string? valueName, uint type, byte[] data, uint size);
}
