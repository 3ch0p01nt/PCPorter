using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace PCPorter.Collectors.Sources;

/// <summary>
/// IRegKey over the live registry, read-only, 64-bit view. Holds NO open handle: each call opens the key, reads,
/// and closes it, so walking tens of thousands of keys never leaks handles. Values are read raw with
/// RegQueryValueExW (type + bytes), exactly like an offline hive, so all decoding is shared and nothing goes
/// through .NET's value conversions (which throw on odd sizes and hide REG_NONE).
/// </summary>
public sealed class LiveRegKey : IRegKey, IDisposable
{
    readonly RegistryHive _root;
    readonly string _path;

    LiveRegKey(RegistryHive root, string path, string name) { _root = root; _path = path; Name = name; }

    public static LiveRegKey? Open(RegistryHive root, string path)
    {
        path = path.Trim('\\');
        using var k = OpenHandle(root, path);
        return k is null ? null : new LiveRegKey(root, path, path.Length == 0 ? root.ToString() : path.Split('\\')[^1]);
    }

    static RegistryKey? OpenHandle(RegistryHive root, string path)
    {
        try
        {
            var baseKey = RegistryKey.OpenBaseKey(root, RegistryView.Registry64);
            if (path.Length == 0) return baseKey;
            try { return baseKey.OpenSubKey(path, writable: false); }
            finally { baseKey.Dispose(); }
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    public string Name { get; }

    public DateTimeOffset? LastWrite
    {
        get
        {
            using var k = OpenHandle(_root, _path);
            if (k is null) return null;
            var rc = RegQueryInfoKey(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out long ft);
            return rc == 0 && ft > 0 ? DateTimeOffset.FromFileTime(ft).ToUniversalTime() : null;
        }
    }

    public IEnumerable<IRegKey> SubKeys
    {
        get
        {
            string[] names;
            using (var k = OpenHandle(_root, _path))
            {
                if (k is null) yield break;
                try { names = k.GetSubKeyNames(); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { yield break; }
            }
            foreach (var n in names) yield return new LiveRegKey(_root, _path.Length == 0 ? n : _path + "\\" + n, n);
        }
    }

    public IEnumerable<string> ValueNames
    {
        get
        {
            using var k = OpenHandle(_root, _path);
            if (k is null) return [];
            try { return k.GetValueNames(); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
        }
    }

    public IRegKey? Open(string relativePath)
    {
        var rel = relativePath.Trim('\\');
        return Open(_root, _path.Length == 0 ? rel : rel.Length == 0 ? _path : _path + "\\" + rel);
    }

    public (RegType Type, byte[] Raw)? GetRaw(string valueName)
    {
        using var k = OpenHandle(_root, _path);
        if (k is null) return null;
        uint size = 0;
        int rc = RegQueryValueEx(k.Handle, valueName, IntPtr.Zero, out uint type, null, ref size);
        if (rc == ErrorFileNotFound) return null;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            if (rc != 0 && rc != ErrorMoreData) return null;
            var data = new byte[size];
            rc = RegQueryValueEx(k.Handle, valueName, IntPtr.Zero, out type, data, ref size);
            if (rc == 0) return (Map(type), size == data.Length ? data : data[..(int)size]);
        }
        return null;
    }

    static RegType Map(uint t) => t switch
    {
        0 => RegType.None, 1 => RegType.String, 2 => RegType.ExpandString, 3 => RegType.Binary, 4 => RegType.DWord,
        5 => RegType.DWordBigEndian, 7 => RegType.MultiString, 11 => RegType.QWord, _ => RegType.Other,
    };

    public void Dispose() { }   // nothing held

    const int ErrorFileNotFound = 2, ErrorMoreData = 234;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int RegQueryValueEx(SafeRegistryHandle hKey, string? valueName, IntPtr reserved, out uint type, byte[]? data, ref uint dataSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryInfoKeyW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int RegQueryInfoKey(SafeRegistryHandle hKey, IntPtr cls, IntPtr clsLen, IntPtr reserved, IntPtr subKeys, IntPtr maxSubKeyLen,
        IntPtr maxClassLen, IntPtr values, IntPtr maxValueNameLen, IntPtr maxValueLen, IntPtr securityDescriptor, out long lastWriteTime);
}
