using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using PCPorter.Collectors.Sources;
using PCPorter.TestKit;
using Win32Registry = Microsoft.Win32.Registry;   // the parser package also has a "Registry" namespace

namespace PCPorter.Collectors.Tests.Sources;

/// <summary>The same expectations for every IRegKey implementation: fake, real offline hive (offreg), and the live registry.</summary>
public abstract class RegKeyContractTests : IDisposable
{
    protected static RegSpec Spec() => RegSpec.Root()
        .Key(@"Microsoft\Windows\CurrentVersion\Uninstall\{GUID-1}", k => k
            .Str("DisplayName", "7-Zip 24.08").Str("SystemComponent", "1").Num("NoModify", 1)
            .QNum("Big", 0x1_0000_0002UL).Exp("InstallLocation", @"%ProgramFiles%\7-Zip")
            .Multi("Tags", "a", "b", "c").Multi("Gaps", "a", "", "b").Bin("Blob", 1, 2, 3).Str("", "default value")
            .Raw("NoneValue", RegType.None, 9, 8)
            .Raw("BigEndian", RegType.DWordBigEndian, 0, 0, 1, 0)
            .Raw("LongDword", RegType.DWord, 5, 0, 0, 0, 0, 0, 0, 0));

    protected abstract IRegKey Build(RegSpec spec);
    public virtual void Dispose() { }

    IRegKey Key => Build(Spec()).Open(@"microsoft\WINDOWS\CurrentVersion\Uninstall\{guid-1}")!;   // case-insensitive path

    [Fact] public void Opens_nested_keys_case_insensitively() => Assert.NotNull(Key);
    [Fact] public void Missing_key_is_null() => Assert.Null(Build(Spec()).Open(@"Microsoft\Nope"));
    [Fact] public void Strings() => Assert.Equal("7-Zip 24.08", Key.GetString("displayname"));
    [Fact] public void Numeric_strings_are_numbers() => Assert.Equal(1, Key.GetNumber("SystemComponent"));
    [Fact] public void DWords() => Assert.Equal(1, Key.GetNumber("NoModify"));
    [Fact] public void QWords() => Assert.Equal(0x1_0000_0002L, Key.GetNumber("Big"));
    [Fact] public void Expand_strings_stay_unexpanded() => Assert.Equal(@"%ProgramFiles%\7-Zip", Key.GetString("InstallLocation"));
    [Fact] public void Multi_strings() => Assert.Equal(["a", "b", "c"], Key.GetMulti("Tags")!);
    [Fact] public void Multi_strings_keep_empty_entries_in_the_middle() => Assert.Equal(["a", "", "b"], Key.GetMulti("Gaps")!);
    [Fact] public void Binary() => Assert.Equal([1, 2, 3], Key.GetBytes("Blob")!);
    [Fact] public void Default_value() => Assert.Equal("default value", Key.GetString(""));
    [Fact] public void Missing_value_is_null() => Assert.Null(Key.GetString("Nope"));
    [Fact] public void Reg_none_is_none_everywhere()
    {
        var (type, raw) = Key.GetRaw("NoneValue")!.Value;
        Assert.Equal(RegType.None, type);
        Assert.Equal([9, 8], raw);
    }
    [Fact] public void Big_endian_dword() => Assert.Equal(256, Key.GetNumber("BigEndian"));
    [Fact] public void Over_long_dword_uses_first_four_bytes() => Assert.Equal(5, Key.GetNumber("LongDword"));
    [Fact] public void Subkeys_and_value_names()
    {
        var sub = Assert.Single(Build(Spec()).Open(@"Microsoft\Windows\CurrentVersion\Uninstall")!.SubKeys);
        Assert.Equal("{GUID-1}", sub.Name, ignoreCase: true);
        Assert.Equal(
            new[] { "", "Big", "BigEndian", "Blob", "DisplayName", "Gaps", "InstallLocation", "LongDword", "NoModify", "NoneValue", "SystemComponent", "Tags" },
            sub.ValueNames.Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
    }
    [Fact] public void Has_last_write_time() => Assert.NotNull(Key.LastWrite);
}

public sealed class FakeRegKeyContract : RegKeyContractTests
{
    protected override IRegKey Build(RegSpec spec) => spec.ToFake();
}

public sealed class ParsedRegKeyContract : RegKeyContractTests
{
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-hive").FullName;
    public override void Dispose() => Directory.Delete(_dir, true);

    protected override IRegKey Build(RegSpec spec)
    {
        var path = Path.Combine(_dir, "SOFTWARE");
        OffregHiveBuilder.Save(spec, path);
        var parsed = HiveParser.Parse(path);
        Assert.Null(parsed.Problem);
        return parsed.Root!;
    }
}

/// <summary>Writes the spec's exact bytes under HKCU\Software\PCPorterTest\{guid} (removed afterwards) and reads it back read-only.</summary>
[Collection("HKCU")]
public sealed class LiveRegKeyContract : RegKeyContractTests
{
    readonly string _path = @"Software\PCPorterTest\" + Guid.NewGuid().ToString("N");

    protected override IRegKey Build(RegSpec spec)
    {
        Win32Registry.CurrentUser.DeleteSubKeyTree(_path, false);
        using (var root = Win32Registry.CurrentUser.CreateSubKey(_path)) Write(root, spec);
        return LiveRegKey.Open(RegistryHive.CurrentUser, _path)!;
    }

    static void Write(RegistryKey key, RegSpec spec)
    {
        foreach (var (name, (type, raw)) in spec.Values)
        {
            var rc = RegSetValueEx(key.Handle, name.Length == 0 ? null : name, 0, RegSpec.Win32Type(type), raw, raw.Length);
            Assert.Equal(0, rc);
        }
        foreach (var child in spec.Keys.Values) using (var sub = key.CreateSubKey(child.Name)) Write(sub, child);
    }

    public override void Dispose()
    {
        Win32Registry.CurrentUser.DeleteSubKeyTree(_path, false);
        using var parent = Win32Registry.CurrentUser.OpenSubKey(@"Software\PCPorterTest", writable: true);
        if (parent is { SubKeyCount: 0, ValueCount: 0 }) Win32Registry.CurrentUser.DeleteSubKey(@"Software\PCPorterTest", false);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegSetValueExW")]
    static extern int RegSetValueEx(SafeRegistryHandle key, string? name, int reserved, uint type, byte[] data, int size);
}

[CollectionDefinition("HKCU", DisableParallelization = true)]
public sealed class HkcuCollection;
