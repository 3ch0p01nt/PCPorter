# PCPorter Phase 1 (Foundation) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** A buildable .NET 10 solution with a tested core (timestamps, settings, case database, encrypted vault, VSS wrapper), a WPF-UI shell (home screen with three tiles, About, crash handler, single instance) and a CLI entry point, publishable as one EXE.

**Architecture:** One WPF EXE (`PCPorter.App`) that runs the GUI with no arguments and the CLI with arguments. Logic lives in class libraries (`Core`, `Security`, later `Collectors`, `Forensics`, `Reports`) so it can be unit-tested without UI. All evidence goes into one SQLite `case.db` per case.

**Tech Stack:** .NET 10, WPF + WPF-UI 4.x, Serilog, System.CommandLine 2.x, Microsoft.Data.Sqlite (FTS5), Konscious Argon2id, `System.Security.Cryptography.AesGcm`, ArxOne.AlphaVSS, xUnit.

Design reference: `docs/plans/2026-11-26-pcporter-design.md`. Root folder below = the repository root (run all commands from there).

---

### Task 1: Solution skeleton

**Files:**
- Create: `global.json`, `Directory.Build.props`, `PCPorter.sln`
- Create projects: `src/PCPorter.App`, `src/PCPorter.Core`, `src/PCPorter.Security`, `tests/PCPorter.Core.Tests`, `tests/PCPorter.Security.Tests`

**Step 1: Pin SDK and shared build settings**

`global.json`:
```json
{ "sdk": { "version": "10.0.100", "rollForward": "latestFeature" } }
```

`Directory.Build.props`:
```xml
<Project>
  <PropertyGroup>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <LangVersion>latest</LangVersion>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <NuGetAudit>true</NuGetAudit>
    <NuGetAuditMode>all</NuGetAuditMode>
    <WarningsAsErrors>$(WarningsAsErrors);NU1903;NU1904</WarningsAsErrors>
    <Version>0.1.0</Version>
  </PropertyGroup>
</Project>
```

**Step 2: Create projects**

```powershell
dotnet new sln -n PCPorter
dotnet new wpf -n PCPorter.App -o src/PCPorter.App -f net10.0
dotnet new classlib -n PCPorter.Core -o src/PCPorter.Core -f net10.0
dotnet new classlib -n PCPorter.Security -o src/PCPorter.Security -f net10.0
dotnet new xunit -n PCPorter.Core.Tests -o tests/PCPorter.Core.Tests -f net10.0
dotnet new xunit -n PCPorter.Security.Tests -o tests/PCPorter.Security.Tests -f net10.0
dotnet sln add (Get-ChildItem -Recurse -Filter *.csproj).FullName
dotnet add src/PCPorter.App reference src/PCPorter.Core src/PCPorter.Security
dotnet add src/PCPorter.Security reference src/PCPorter.Core
dotnet add tests/PCPorter.Core.Tests reference src/PCPorter.Core
dotnet add tests/PCPorter.Security.Tests reference src/PCPorter.Security
```

Set `<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework>` in Core, Security and both test projects (Windows APIs needed). Delete the template `Class1.cs` / `UnitTest1.cs` files.

**Step 3: Build**

Run: `dotnet build`
Expected: `Build succeeded. 0 Warning(s) 0 Error(s)`

**Step 4: Commit**
```powershell
git add -A; git commit -m "chore: solution skeleton on .NET 10"
```

---

### Task 2: Timestamp converters (used by every forensic parser)

**Files:**
- Create: `src/PCPorter.Core/Time/Timestamps.cs`
- Test: `tests/PCPorter.Core.Tests/Time/TimestampsTests.cs`

**Step 1: Write the failing tests**

```csharp
using PCPorter.Core.Time;

namespace PCPorter.Core.Tests.Time;

public class TimestampsTests
{
    static readonly DateTimeOffset Y2K = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact] public void WebKit_converts() =>   // Chromium: microseconds since 1601-01-01
        Assert.Equal(Y2K, Timestamps.FromWebKit(12_591_158_400_000_000L));

    [Fact] public void PRTime_converts() =>   // Firefox: microseconds since 1970-01-01
        Assert.Equal(Y2K, Timestamps.FromPRTime(946_684_800_000_000L));

    [Fact] public void FileTime_converts() => // Windows: 100ns ticks since 1601-01-01
        Assert.Equal(Y2K, Timestamps.FromFileTime(125_911_584_000_000_000L));

    [Theory, InlineData(0L), InlineData(-1L)]
    public void Zero_or_negative_is_null(long v)
    {
        Assert.Null(Timestamps.FromWebKit(v));
        Assert.Null(Timestamps.FromPRTime(v));
        Assert.Null(Timestamps.FromFileTime(v));
    }

    [Fact] public void Absurd_values_are_null() =>  // corrupt data must not throw
        Assert.Null(Timestamps.FromWebKit(long.MaxValue));
}
```

**Step 2: Run to verify it fails**

Run: `dotnet test tests/PCPorter.Core.Tests --filter TimestampsTests`
Expected: FAIL, build error `The type or namespace name 'Time' does not exist`

**Step 3: Implement**

```csharp
namespace PCPorter.Core.Time;

/// <summary>Converts raw forensic timestamps to UTC. Returns null for empty or corrupt values instead of throwing.</summary>
public static class Timestamps
{
    static readonly DateTimeOffset Epoch1601 = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Epoch1970 = DateTimeOffset.UnixEpoch;
    static readonly DateTimeOffset Min = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Max = new(2200, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static DateTimeOffset? FromWebKit(long micros) => FromTicks(Epoch1601, micros, 10);
    public static DateTimeOffset? FromPRTime(long micros) => FromTicks(Epoch1970, micros, 10);
    public static DateTimeOffset? FromFileTime(long ticks) => FromTicks(Epoch1601, ticks, 1);

    static DateTimeOffset? FromTicks(DateTimeOffset epoch, long value, long ticksPerUnit)
    {
        if (value <= 0) return null;
        try
        {
            var result = epoch.AddTicks(checked(value * ticksPerUnit));
            return result < Min || result > Max ? null : result;
        }
        catch (Exception e) when (e is OverflowException or ArgumentOutOfRangeException) { return null; }
    }
}
```

**Step 4: Run to verify pass**

Run: `dotnet test tests/PCPorter.Core.Tests --filter TimestampsTests`
Expected: `Passed! - Failed: 0, Passed: 7`

**Step 5: Commit**
```powershell
git add -A; git commit -m "feat(core): forensic timestamp converters"
```

---

### Task 3: App paths and settings store (atomic save)

**Files:**
- Create: `src/PCPorter.Core/Config/AppSettings.cs`, `src/PCPorter.Core/Config/SettingsStore.cs`
- Test: `tests/PCPorter.Core.Tests/Config/SettingsStoreTests.cs`

**Step 1: Failing tests**

```csharp
using PCPorter.Core.Config;

namespace PCPorter.Core.Tests.Config;

public class SettingsStoreTests : IDisposable
{
    readonly string _dir = Directory.CreateTempSubdirectory("pcporter-test").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    [Fact] public void Missing_file_returns_defaults()
    {
        var s = new SettingsStore(_dir).Load();
        Assert.False(s.FirstRunCompleted);
        Assert.Equal(1, s.SchemaVersion);
    }

    [Fact] public void Save_then_load_round_trips()
    {
        var store = new SettingsStore(_dir);
        store.Save(new AppSettings { FirstRunCompleted = true, Theme = "Dark" });
        var s = store.Load();
        Assert.True(s.FirstRunCompleted);
        Assert.Equal("Dark", s.Theme);
        Assert.False(File.Exists(Path.Combine(_dir, "settings.json.tmp")));
    }

    [Fact] public void Corrupt_file_returns_defaults_and_keeps_backup()
    {
        File.WriteAllText(Path.Combine(_dir, "settings.json"), "{ not json");
        var s = new SettingsStore(_dir).Load();
        Assert.False(s.FirstRunCompleted);
        Assert.True(File.Exists(Path.Combine(_dir, "settings.json.corrupt")));
    }
}
```

**Step 2: Run, expect build failure** (`SettingsStore` not found).

**Step 3: Implement**

```csharp
namespace PCPorter.Core.Config;

public sealed record AppSettings
{
    public int SchemaVersion { get; init; } = 1;
    public bool FirstRunCompleted { get; init; }
    public string Theme { get; init; } = "System";
    public bool CheckForUpdates { get; init; }
    public List<string> RecentCases { get; init; } = [];
}
```

```csharp
using System.Text.Json;

namespace PCPorter.Core.Config;

public sealed class SettingsStore(string directory)
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    string FilePath => Path.Combine(directory, "settings.json");

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCPorter");

    public AppSettings Load()
    {
        if (!File.Exists(FilePath)) return new AppSettings();
        try { return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Json) ?? new AppSettings(); }
        catch (JsonException)
        {
            File.Copy(FilePath, FilePath + ".corrupt", overwrite: true);
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(directory);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Json));
        File.Move(tmp, FilePath, overwrite: true);   // atomic replace: a crash never leaves half a file
    }
}
```

**Step 4: Run** `dotnet test tests/PCPorter.Core.Tests --filter SettingsStoreTests` → 3 passed.

**Step 5: Commit** `git add -A; git commit -m "feat(core): settings store with atomic save"`

---

### Task 4: Case database (SQLite + FTS5)

**Files:**
- Create: `src/PCPorter.Core/Case/CaseDb.cs`, `src/PCPorter.Core/Case/Artifact.cs`
- Test: `tests/PCPorter.Core.Tests/Case/CaseDbTests.cs`

**Step 1: Add package** `dotnet add src/PCPorter.Core package Microsoft.Data.Sqlite`

**Step 2: Failing tests**

```csharp
using PCPorter.Core.Case;

namespace PCPorter.Core.Tests.Case;

public class CaseDbTests : IDisposable
{
    readonly string _path = Path.Combine(Path.GetTempPath(), $"case-{Guid.NewGuid():N}.db");
    public void Dispose() { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); File.Delete(_path); }

    static Artifact Visit(string url, DateTimeOffset ts) => new(
        TsUtc: ts, Category: "WebHistory", Source: "Chrome/Default", Artifact: "History.visits",
        User: "bob", Action: "Visit", Subject: url, Detail: "typed", Confidence: Confidence.Existed);

    [Fact] public void Insert_and_count_by_category()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("https://example.com", DateTimeOffset.UtcNow), Visit("https://contoso.com", DateTimeOffset.UtcNow)]);
        Assert.Equal(2, db.CountByCategory()["WebHistory"]);
    }

    [Fact] public void Full_text_search_finds_subject_and_detail()
    {
        using var db = CaseDb.Open(_path);
        db.Insert([Visit("https://example.com/cats", DateTimeOffset.UtcNow), Visit("https://contoso.com", DateTimeOffset.UtcNow)]);
        var hits = db.Search("cats");
        Assert.Single(hits);
        Assert.Contains("cats", hits[0].Subject);
    }

    [Fact] public void Reopen_keeps_data_and_schema_version()
    {
        using (var db = CaseDb.Open(_path)) db.Insert([Visit("https://a.com", DateTimeOffset.UtcNow)]);
        using var again = CaseDb.Open(_path);
        Assert.Equal(1, again.SchemaVersion);
        Assert.Equal(1, again.CountByCategory()["WebHistory"]);
    }
}
```

**Step 3: Run, expect build failure.**

**Step 4: Implement**

```csharp
namespace PCPorter.Core.Case;

public enum Confidence { Existed = 0, Ran = 1 }   // "proves it existed" vs "proves it ran"

public sealed record Artifact(
    DateTimeOffset? TsUtc, string Category, string Source, string Artifact,
    string? User, string Action, string Subject, string? Detail, Confidence Confidence);
```

```csharp
using Microsoft.Data.Sqlite;

namespace PCPorter.Core.Case;

/// <summary>One SQLite file per case. Every collector writes normalized rows here; reports and the workbench read from it.</summary>
public sealed class CaseDb : IDisposable
{
    const int CurrentSchema = 1;
    readonly SqliteConnection _conn;
    CaseDb(SqliteConnection conn) => _conn = conn;

    public int SchemaVersion => Convert.ToInt32(Scalar("PRAGMA user_version"));

    public static CaseDb Open(string path)
    {
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        conn.Open();
        var db = new CaseDb(conn);
        db.Exec("PRAGMA journal_mode=WAL;");
        if (db.SchemaVersion == 0) db.CreateSchema();
        return db;
    }

    void CreateSchema() => Exec($"""
        CREATE TABLE artifacts(
          id INTEGER PRIMARY KEY, ts_utc INTEGER, category TEXT NOT NULL, source TEXT NOT NULL,
          artifact TEXT NOT NULL, user TEXT, action TEXT NOT NULL, subject TEXT NOT NULL,
          detail TEXT, confidence INTEGER NOT NULL);
        CREATE INDEX ix_artifacts_ts ON artifacts(ts_utc);
        CREATE INDEX ix_artifacts_cat ON artifacts(category);
        CREATE VIRTUAL TABLE artifacts_fts USING fts5(subject, detail, content='artifacts', content_rowid='id');
        CREATE TRIGGER artifacts_ai AFTER INSERT ON artifacts BEGIN
          INSERT INTO artifacts_fts(rowid, subject, detail) VALUES (new.id, new.subject, new.detail);
        END;
        CREATE TABLE tags(artifact_id INTEGER NOT NULL REFERENCES artifacts(id), tag TEXT NOT NULL, note TEXT,
          PRIMARY KEY(artifact_id, tag));
        PRAGMA user_version = {CurrentSchema};
        """);

    public void Insert(IEnumerable<Artifact> rows)
    {
        using var tx = _conn.BeginTransaction();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO artifacts(ts_utc, category, source, artifact, user, action, subject, detail, confidence)
            VALUES ($ts, $cat, $src, $art, $user, $act, $sub, $det, $conf)
            """;
        string[] names = ["$ts", "$cat", "$src", "$art", "$user", "$act", "$sub", "$det", "$conf"];
        foreach (var n in names) cmd.Parameters.Add(new SqliteParameter(n, null));
        foreach (var r in rows)
        {
            object?[] values = [r.TsUtc?.ToUnixTimeMilliseconds(), r.Category, r.Source, r.Artifact,
                                r.User, r.Action, r.Subject, r.Detail, (int)r.Confidence];
            for (var i = 0; i < values.Length; i++) cmd.Parameters[i].Value = values[i] ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public Dictionary<string, int> CountByCategory()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT category, COUNT(*) FROM artifacts GROUP BY category";
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, int>();
        while (r.Read()) result[r.GetString(0)] = r.GetInt32(1);
        return result;
    }

    public List<Artifact> Search(string query, int limit = 500)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            SELECT a.ts_utc, a.category, a.source, a.artifact, a.user, a.action, a.subject, a.detail, a.confidence
            FROM artifacts_fts f JOIN artifacts a ON a.id = f.rowid
            WHERE artifacts_fts MATCH $q ORDER BY a.ts_utc LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$q", '"' + query.Replace("\"", "\"\"") + '"');  // treat input as a phrase, not FTS syntax
        cmd.Parameters.AddWithValue("$limit", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<Artifact>();
        while (r.Read())
            list.Add(new Artifact(
                r.IsDBNull(0) ? null : DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(0)),
                r.GetString(1), r.GetString(2), r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4),
                r.GetString(5), r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7), (Confidence)r.GetInt32(8)));
        return list;
    }

    void Exec(string sql) { using var c = _conn.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }
    object? Scalar(string sql) { using var c = _conn.CreateCommand(); c.CommandText = sql; return c.ExecuteScalar(); }
    public void Dispose() => _conn.Dispose();
}
```

**Step 5: Run** `dotnet test tests/PCPorter.Core.Tests --filter CaseDbTests` → 3 passed. (If FTS5 is missing from the bundled SQLite, add package `SQLitePCLRaw.bundle_e_sqlite3`.)

**Step 6: Commit** `git add -A; git commit -m "feat(core): case database with FTS5 search and tags table"`

---

### Task 5: Encrypted vault

Format: `PCPV` magic, version byte, Argon2id params + 16-byte salt (header, also used as associated data), then chunks of up to 1 MiB, each `[4-byte length][ciphertext][16-byte tag]`. Nonce per chunk = 4 random header bytes + 8-byte chunk counter. Associated data per chunk = header + chunk index + "final" flag, so reordering, swapping or truncating chunks fails authentication.

**Files:**
- Create: `src/PCPorter.Security/Vault/VaultFile.cs`, `src/PCPorter.Security/Vault/KdfParams.cs`
- Test: `tests/PCPorter.Security.Tests/Vault/VaultFileTests.cs`

**Step 1: Add package** `dotnet add src/PCPorter.Security package Konscious.Security.Cryptography.Argon2`

**Step 2: Failing tests**

```csharp
using System.Security.Cryptography;
using PCPorter.Security.Vault;

namespace PCPorter.Security.Tests.Vault;

public class VaultFileTests
{
    static readonly KdfParams Fast = new(MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1); // tests only
    static byte[] Data(int n) { var b = new byte[n]; Random.Shared.NextBytes(b); return b; }

    static byte[] Encrypt(byte[] plain, string pass)
    {
        using var input = new MemoryStream(plain); using var output = new MemoryStream();
        VaultFile.Encrypt(input, output, pass.ToCharArray(), Fast);
        return output.ToArray();
    }
    static byte[] Decrypt(byte[] cipher, string pass)
    {
        using var input = new MemoryStream(cipher); using var output = new MemoryStream();
        VaultFile.Decrypt(input, output, pass.ToCharArray());
        return output.ToArray();
    }

    [Theory, InlineData(0), InlineData(10), InlineData(1024 * 1024), InlineData(3 * 1024 * 1024 + 7)]
    public void Round_trips(int size)
    {
        var plain = Data(size);
        Assert.Equal(plain, Decrypt(Encrypt(plain, "correct horse battery staple"), "correct horse battery staple"));
    }

    [Fact] public void Wrong_passphrase_fails() =>
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(Encrypt(Data(100), "right"), "wrong"));

    [Fact] public void Flipped_bit_fails()
    {
        var c = Encrypt(Data(5000), "p"); c[^20] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c, "p"));
    }

    [Fact] public void Truncated_file_fails()
    {
        var c = Encrypt(Data(3 * 1024 * 1024), "p");          // 3 full chunks + empty final chunk
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(c[..(c.Length - 30)], "p"));
    }

    [Fact] public void Not_a_vault_fails() =>
        Assert.Throws<InvalidDataException>(() => Decrypt("hello world, not a vault"u8.ToArray(), "p"));
}
```

**Step 3: Run, expect build failure.**

**Step 4: Implement**

```csharp
namespace PCPorter.Security.Vault;

/// <summary>Argon2id cost. Default = ~1 s on a modern PC; stored in the vault header.</summary>
public sealed record KdfParams(int MemoryKiB = 256 * 1024, int Iterations = 3, int Parallelism = 4);
```

```csharp
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace PCPorter.Security.Vault;

public static class VaultFile
{
    const int ChunkSize = 1024 * 1024, TagSize = 16, NonceSize = 12, SaltSize = 16, PrefixSize = 4;
    static readonly byte[] Magic = "PCPV"u8.ToArray();
    const byte Version = 1;
    // header: magic(4) ver(1) mem(4) iter(4) par(4) salt(16) noncePrefix(4) = 37 bytes
    const int HeaderSize = 4 + 1 + 12 + SaltSize + PrefixSize;

    public static void Encrypt(Stream input, Stream output, char[] passphrase, KdfParams? kdf = null)
    {
        kdf ??= new KdfParams();
        var header = new byte[HeaderSize];
        Magic.CopyTo(header, 0); header[4] = Version;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(5), kdf.MemoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(9), kdf.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(13), kdf.Parallelism);
        RandomNumberGenerator.Fill(header.AsSpan(17, SaltSize + PrefixSize));
        output.Write(header);

        var key = DeriveKey(passphrase, header);
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            var plain = new byte[ChunkSize]; var cipher = new byte[ChunkSize]; var tag = new byte[TagSize];
            var len = new byte[4];
            // A full chunk is never final: the stream always ends with a short (possibly empty) final chunk,
            // so cutting off the end of the file is detected.
            for (long index = 0; ; index++)
            {
                int read = ReadFull(input, plain);
                bool final = read < ChunkSize;
                gcm.Encrypt(Nonce(header, index), plain.AsSpan(0, read), cipher.AsSpan(0, read), tag, Aad(header, index, final));
                BinaryPrimitives.WriteInt32LittleEndian(len, read);
                output.Write(len); output.Write(cipher, 0, read); output.Write(tag);
                if (final) break;
            }
            CryptographicOperations.ZeroMemory(plain);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public static void Decrypt(Stream input, Stream output, char[] passphrase)
    {
        var header = new byte[HeaderSize];
        if (ReadFull(input, header) != HeaderSize || !header.AsSpan(0, 4).SequenceEqual(Magic) || header[4] != Version)
            throw new InvalidDataException("Not a PCPorter vault file.");

        var key = DeriveKey(passphrase, header);
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            var lenBuf = new byte[4]; var tag = new byte[TagSize];
            for (long index = 0; ; index++)
            {
                if (ReadFull(input, lenBuf) != 4) throw new AuthenticationTagMismatchException("Vault is truncated.");
                int len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
                if (len is < 0 or > ChunkSize) throw new AuthenticationTagMismatchException("Corrupt chunk length.");
                var cipher = new byte[len]; var plain = new byte[len];
                if (ReadFull(input, cipher) != len || ReadFull(input, tag) != TagSize)
                    throw new AuthenticationTagMismatchException("Vault is truncated.");
                bool final = len < ChunkSize;
                gcm.Decrypt(Nonce(header, index), cipher, tag, plain, Aad(header, index, final)); // throws on tamper/wrong key
                output.Write(plain);
                CryptographicOperations.ZeroMemory(plain);
                if (final) return;
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    static byte[] DeriveKey(char[] passphrase, byte[] header)
    {
        var passBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            using var argon = new Argon2id(passBytes)
            {
                Salt = header[17..(17 + SaltSize)],
                MemorySize = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(5)),
                Iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(9)),
                DegreeOfParallelism = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(13)),
            };
            return argon.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(passBytes); }
    }

    static byte[] Nonce(byte[] header, long index)
    {
        var n = new byte[NonceSize];
        header.AsSpan(17 + SaltSize, PrefixSize).CopyTo(n);
        BinaryPrimitives.WriteInt64LittleEndian(n.AsSpan(PrefixSize), index);
        return n;
    }

    static byte[] Aad(byte[] header, long index, bool final)
    {
        var aad = new byte[HeaderSize + 9];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(HeaderSize), index);
        aad[^1] = final ? (byte)1 : (byte)0;
        return aad;
    }

    static int ReadFull(Stream s, Span<byte> buf)
    {
        int total = 0;
        while (total < buf.Length) { int n = s.Read(buf[total..]); if (n == 0) break; total += n; }
        return total;
    }
}
```

**Step 5: Run** `dotnet test tests/PCPorter.Security.Tests` → 8 passed.

**Step 6: Commit** `git add -A; git commit -m "feat(security): chunked AES-GCM vault with Argon2id key"`

---

### Task 6: VSS snapshot wrapper

**Files:**
- Create: `src/PCPorter.Core/Snapshots/ISnapshotProvider.cs`, `src/PCPorter.Core/Snapshots/VssSnapshotProvider.cs`
- Test: `tests/PCPorter.Core.Tests/Snapshots/VssSnapshotProviderTests.cs`

**Step 1: Add package** `dotnet add src/PCPorter.Core package ArxOne.AlphaVSS`

**Step 2: Failing test (runs only elevated; skipped otherwise)**

```csharp
using System.Security.Principal;
using PCPorter.Core.Snapshots;

namespace PCPorter.Core.Tests.Snapshots;

public class VssSnapshotProviderTests
{
    static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact] public void Snapshot_exposes_locked_file_and_cleans_up()
    {
        if (!IsAdmin) { Assert.Skip("Requires an elevated test run."); return; }
        var ntuser = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "NTUSER.DAT");
        string device;
        using (var snap = new VssSnapshotProvider().Create("C:\\"))
        {
            device = snap.DeviceRoot;
            var mapped = snap.Map(ntuser);
            using var fs = File.OpenRead(mapped);   // live NTUSER.DAT is locked; the snapshot copy is not
            Assert.True(fs.Length > 0);
        }
        Assert.False(Directory.Exists(device + "\\Windows"));  // snapshot deleted on dispose
    }
}
```

**Step 3: Implement**

```csharp
namespace PCPorter.Core.Snapshots;

public interface ISnapshot : IDisposable
{
    string DeviceRoot { get; }               // e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12
    string Map(string livePath);             // C:\Users\x\file -> \\?\GLOBALROOT\...\Users\x\file
}
public interface ISnapshotProvider { ISnapshot Create(string volumeRoot); }
```

```csharp
using Alphaleonis.Win32.Vss;

namespace PCPorter.Core.Snapshots;

public sealed class VssSnapshotProvider : ISnapshotProvider
{
    public ISnapshot Create(string volumeRoot)
    {
        var vss = VssFactoryProvider.Default.GetVssFactory();
        var backup = vss.CreateVssBackupComponents();
        backup.InitializeForBackup(null);
        backup.SetContext(VssSnapshotContext.Backup);
        backup.SetBackupState(false, true, VssBackupType.Copy, false);
        backup.GatherWriterMetadata();
        var setId = backup.StartSnapshotSet();
        var snapId = backup.AddToSnapshotSet(volumeRoot);
        backup.PrepareForBackup();
        backup.DoSnapshotSet();
        var props = backup.GetSnapshotProperties(snapId);
        return new Snapshot(backup, setId, volumeRoot, props.SnapshotDeviceObject);
    }

    sealed class Snapshot(IVssBackupComponents backup, Guid setId, string volumeRoot, string device) : ISnapshot
    {
        public string DeviceRoot => device;
        public string Map(string livePath) =>
            Path.Combine(device + "\\", Path.GetRelativePath(volumeRoot, livePath));
        public void Dispose()
        {
            try { backup.DeleteSnapshotSet(setId, true); } finally { backup.Dispose(); }
        }
    }
}
```

**Step 4: Run elevated** - from an admin PowerShell: `dotnet test tests/PCPorter.Core.Tests --filter VssSnapshotProviderTests`. Expected: PASS (non-elevated: Skipped). If the AlphaVSS API names differ in the installed version, check its README and adjust; keep the `ISnapshot` interface unchanged.

**Step 5: Commit** `git add -A; git commit -m "feat(core): VSS snapshot provider"`

---

### Task 7: CLI entry point with exit codes

**Files:**
- Create: `src/PCPorter.Core/Cli/ExitCodes.cs`, `src/PCPorter.Core/Cli/CliApp.cs`
- Test: `tests/PCPorter.Core.Tests/Cli/CliAppTests.cs`

**Step 1: Add package** `dotnet add src/PCPorter.Core package System.CommandLine`

**Step 2: Failing tests**

```csharp
using PCPorter.Core.Cli;

namespace PCPorter.Core.Tests.Cli;

public class CliAppTests
{
    [Fact] public void Unknown_command_is_bad_args() =>
        Assert.Equal(ExitCodes.BadArguments, CliApp.Run(["frobnicate"], isElevated: true));

    [Fact] public void Backup_requires_elevation() =>
        Assert.Equal(ExitCodes.NotElevated, CliApp.Run(["backup", "--dest", "E:\\"], isElevated: false));

    [Fact] public void Backup_without_dest_is_bad_args() =>
        Assert.Equal(ExitCodes.BadArguments, CliApp.Run(["backup"], isElevated: true));

    [Fact] public void Version_succeeds() =>
        Assert.Equal(ExitCodes.Ok, CliApp.Run(["--version"], isElevated: false));
}
```

**Step 3: Implement**

```csharp
namespace PCPorter.Core.Cli;

public static class ExitCodes
{
    public const int Ok = 0, Partial = 1, Failed = 2, BadArguments = 3, NotElevated = 4;
}
```

```csharp
using System.CommandLine;

namespace PCPorter.Core.Cli;

public static class CliApp
{
    public static int Run(string[] args, bool isElevated)
    {
        var dest = new Option<DirectoryInfo>("--dest") { Description = "Backup destination folder", Required = true };
        var from = new Option<DirectoryInfo>("--from") { Description = "Existing backup or case folder", Required = true };
        var quiet = new Option<bool>("--quiet") { Description = "No prompts; log only" };

        var backup = new Command("backup", "Back up this PC") { dest, quiet };
        backup.SetAction(_ => isElevated ? ExitCodes.Ok /* Phase 5 wires the engine */ : ExitCodes.NotElevated);

        var report = new Command("report", "Generate HTML reports from a backup") { from, quiet };
        report.SetAction(_ => ExitCodes.Ok /* Phase 3 */);

        var root = new RootCommand("PCPorter - move your PC and explore its history") { backup, report };
        var parsed = root.Parse(args);
        if (parsed.Errors.Count > 0)
        {
            foreach (var e in parsed.Errors) Console.Error.WriteLine(e.Message);
            return ExitCodes.BadArguments;
        }
        return parsed.Invoke();
    }
}
```

**Step 4: Run** `dotnet test tests/PCPorter.Core.Tests --filter CliAppTests` → 4 passed. (System.CommandLine 2.x API: if `Required`/`SetAction` names differ in the installed version, follow its docs; tests define the contract.)

**Step 5: Commit** `git add -A; git commit -m "feat(core): CLI with documented exit codes"`

---

### Task 8: WPF-UI shell (home screen, theme, About, crash handler, single instance, logging)

**Files:**
- Modify: `src/PCPorter.App/PCPorter.App.csproj`, `App.xaml`, `App.xaml.cs`, `MainWindow.xaml`, `MainWindow.xaml.cs`
- Create: `src/PCPorter.App/app.manifest`, `src/PCPorter.App/Views/HomePage.xaml(.cs)`, `src/PCPorter.App/Views/AboutPage.xaml(.cs)`, `src/PCPorter.App/Infrastructure/Logging.cs`, `src/PCPorter.App/Infrastructure/CrashHandler.cs`

**Step 1: Packages**
```powershell
dotnet add src/PCPorter.App package WPF-UI
dotnet add src/PCPorter.App package Serilog
dotnet add src/PCPorter.App package Serilog.Sinks.File
```

**Step 2: csproj properties** (inside the main `PropertyGroup`):
```xml
<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework>
<UseWPF>true</UseWPF>
<OutputType>WinExe</OutputType>
<ApplicationManifest>app.manifest</ApplicationManifest>
<AssemblyName>PCPorter</AssemblyName>
```

**Step 3: `app.manifest`** - `requireAdministrator`, per-monitor DPI v2, long paths:
```xml
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2"><security><requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
    <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
  </requestedPrivileges></security></trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>
    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
  </windowsSettings></application>
</assembly>
```

**Step 4: `App.xaml`** - WPF-UI theme dictionaries, no StartupUri:
```xml
<Application x:Class="PCPorter.App.App"
             xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml">
  <Application.Resources>
    <ResourceDictionary>
      <ResourceDictionary.MergedDictionaries>
        <ui:ThemesDictionary Theme="Dark" />
        <ui:ControlsDictionary />
      </ResourceDictionary.MergedDictionaries>
    </ResourceDictionary>
  </Application.Resources>
</Application>
```

**Step 5: `App.xaml.cs`** - CLI vs GUI, single instance, logging, crash handler:
```csharp
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using PCPorter.App.Infrastructure;
using PCPorter.Core.Cli;

namespace PCPorter.App;

public partial class App : Application
{
    Mutex? _single;

    protected override void OnStartup(StartupEventArgs e)
    {
        Logging.Init();
        if (e.Args.Length > 0)
        {
            AttachConsole(-1);   // print to the console that launched us
            var admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            Shutdown(CliApp.Run(e.Args, admin));
            return;
        }
        _single = new Mutex(true, @"Global\PCPorter-7d1f6a2e", out bool first);
        if (!first) { MessageBox.Show("PCPorter is already running."); Shutdown(0); return; }
        CrashHandler.Install(this);
        base.OnStartup(e);
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e) { _single?.Dispose(); Logging.Close(); base.OnExit(e); }

    [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);
}
```

**Step 6: `Infrastructure/Logging.cs` and `CrashHandler.cs`**
```csharp
using Serilog;

namespace PCPorter.App.Infrastructure;

public static class Logging
{
    public static string Folder { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PCPorter", "logs");

    public static void Init() => Log.Logger = new LoggerConfiguration()
        .WriteTo.File(Path.Combine(Folder, "pcporter-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14)
        .CreateLogger();

    public static void Close() => Log.CloseAndFlush();
}
```
```csharp
using System.Windows;
using Serilog;

namespace PCPorter.App.Infrastructure;

public static class CrashHandler
{
    public static void Install(Application app)
    {
        app.DispatcherUnhandledException += (_, e) => { Report(e.Exception); e.Handled = true; };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Report(e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => { Report(e.Exception); e.SetObserved(); };
    }

    static void Report(Exception? ex)
    {
        Log.Fatal(ex, "Unhandled exception");
        MessageBox.Show(
            $"Something went wrong and PCPorter stopped this action.\n\nThe details are saved in the log folder:\n{Logging.Folder}",
            "PCPorter", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
```

**Step 7: `MainWindow.xaml`** - FluentWindow with Mica, title bar, NavigationView (Home, About):
```xml
<ui:FluentWindow x:Class="PCPorter.App.MainWindow"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"
    xmlns:views="clr-namespace:PCPorter.App.Views"
    Title="PCPorter" Width="1200" Height="780" MinWidth="900" MinHeight="600"
    WindowBackdropType="Mica" ExtendsContentIntoTitleBar="True" WindowStartupLocation="CenterScreen">
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
    <ui:TitleBar Grid.Row="0" Title="PCPorter  (running as administrator)" />
    <ui:NavigationView Grid.Row="1" x:Name="Nav" PaneDisplayMode="Left" IsBackButtonVisible="Collapsed">
      <ui:NavigationView.MenuItems>
        <ui:NavigationViewItem Content="Home" TargetPageType="{x:Type views:HomePage}">
          <ui:NavigationViewItem.Icon><ui:SymbolIcon Symbol="Home24"/></ui:NavigationViewItem.Icon>
        </ui:NavigationViewItem>
      </ui:NavigationView.MenuItems>
      <ui:NavigationView.FooterMenuItems>
        <ui:NavigationViewItem Content="About" TargetPageType="{x:Type views:AboutPage}">
          <ui:NavigationViewItem.Icon><ui:SymbolIcon Symbol="Info24"/></ui:NavigationViewItem.Icon>
        </ui:NavigationViewItem>
      </ui:NavigationView.FooterMenuItems>
    </ui:NavigationView>
  </Grid>
</ui:FluentWindow>
```
`MainWindow.xaml.cs`:
```csharp
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace PCPorter.App;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        SystemThemeWatcher.Watch(this);           // follow Windows light/dark + accent
        Loaded += (_, _) => Nav.Navigate(typeof(Views.HomePage));
    }
}
```

**Step 8: `Views/HomePage.xaml`** - three big tiles (actions wired in later phases):
```xml
<Page x:Class="PCPorter.App.Views.HomePage"
      xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml">
  <StackPanel Margin="32">
    <TextBlock Text="What would you like to do?" FontSize="28" FontWeight="SemiBold" Margin="0,0,0,24"/>
    <UniformGrid Columns="3">
      <ui:CardAction Margin="0,0,12,0" Icon="{ui:SymbolIcon ArrowSwap24}" AutomationProperties.Name="Move to my new PC">
        <StackPanel><TextBlock Text="Move to my new PC" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock Text="Back up this PC, or restore a backup onto a new one, without bringing viruses along." TextWrapping="Wrap" Opacity="0.8"/></StackPanel>
      </ui:CardAction>
      <ui:CardAction Margin="6,0" Icon="{ui:SymbolIcon History24}" AutomationProperties.Name="Explore my PC's history">
        <StackPanel><TextBlock Text="Explore my PC's history" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock Text="Web history, viewed images, and everything this PC has logged." TextWrapping="Wrap" Opacity="0.8"/></StackPanel>
      </ui:CardAction>
      <ui:CardAction Margin="12,0,0,0" Icon="{ui:SymbolIcon ShieldCheckmark24}" AutomationProperties.Name="Check health and security">
        <StackPanel><TextBlock Text="Check health and security" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock Text="Antivirus, startup programs, disk and battery health, and a readiness score." TextWrapping="Wrap" Opacity="0.8"/></StackPanel>
      </ui:CardAction>
    </UniformGrid>
  </StackPanel>
</Page>
```
`HomePage.xaml.cs`: `public partial class HomePage : Page { public HomePage() => InitializeComponent(); }`

**Step 9: `Views/AboutPage.xaml`** - version, log folder button:
```xml
<Page x:Class="PCPorter.App.Views.AboutPage"
      xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml">
  <StackPanel Margin="32">
    <TextBlock Text="PCPorter" FontSize="28" FontWeight="SemiBold"/>
    <TextBlock x:Name="VersionText" Margin="0,4,0,16" Opacity="0.8"/>
    <TextBlock Text="Everything stays on this PC. No telemetry." Margin="0,0,0,16"/>
    <ui:Button Content="Open log folder" Icon="{ui:SymbolIcon FolderOpen24}" Click="OpenLogs_Click"/>
  </StackPanel>
</Page>
```
```csharp
using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using PCPorter.App.Infrastructure;

namespace PCPorter.App.Views;

public partial class AboutPage : Page
{
    public AboutPage()
    {
        InitializeComponent();
        var v = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        VersionText.Text = $"Version {v}  ·  .NET {Environment.Version}";
    }

    void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(Logging.Folder);
        Process.Start("explorer.exe", Logging.Folder);
    }
}
```

**Step 10: Build and run**

Run: `dotnet build` then `dotnet run --project src/PCPorter.App` (accept the UAC prompt).
Expected: Mica window with title bar, left nav (Home, About), three tiles on Home, About shows version and opens the log folder. Launching a second copy shows "already running". `dotnet run --project src/PCPorter.App -- frobnicate` exits with code 3.

**Step 11: Commit** `git add -A; git commit -m "feat(app): WPF-UI shell with home tiles, About, logging, crash handler"`

---

### Task 9: Single-file publish smoke test

**Files:**
- Create: `src/PCPorter.App/Properties/PublishProfiles/win-x64.pubxml`

**Step 1: Publish profile**
```xml
<Project>
  <PropertyGroup>
    <Configuration>Release</Configuration>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <SelfContained>true</SelfContained>
    <PublishSingleFile>true</PublishSingleFile>
    <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
    <EnableCompressionInSingleFile>false</EnableCompressionInSingleFile>
    <PublishReadyToRun>true</PublishReadyToRun>
    <PublishTrimmed>false</PublishTrimmed>
    <PublishDir>..\..\publish\</PublishDir>
  </PropertyGroup>
</Project>
```

**Step 2: Publish**

Run: `dotnet publish src/PCPorter.App -p:PublishProfile=win-x64`
Expected: `publish\PCPorter.exe` exists (roughly 100-170 MB), plus no loose DLLs other than optional `.pdb`.

**Step 3: Smoke**

Run: `.\publish\PCPorter.exe --version; $LASTEXITCODE` → prints version, exit code 0. Double-click the EXE → UAC prompt, then the shell opens. Run a Defender scan on it: `& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "$PWD\publish\PCPorter.exe"` → `found no threats`.

**Step 4: Commit** `git add -A; git commit -m "build: single-file publish profile"`

---

### Task 10: Close out Phase 1

- Run full suite: `dotnet test` → all green (VSS test skipped unless elevated; run once elevated).
- Tick Phase 1 boxes in `tasks/todo.md`, add a short Review note (what was built, anything deferred).
- Commit: `git add -A; git commit -m "docs: Phase 1 complete"`

Next plan: Phase 2 (read-only scanners: inventory, AV detection, health/readiness, persistence audit, dead-PC rescue source).
