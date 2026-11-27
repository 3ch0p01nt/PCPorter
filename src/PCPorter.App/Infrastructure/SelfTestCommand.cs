using System.CommandLine;
using System.IO;
using PCPorter.Collectors.Sources;
using PCPorter.Core.Case;
using PCPorter.Core.Cli;
using PCPorter.Core.Snapshots;
using PCPorter.Security.Vault;

namespace PCPorter.App.Infrastructure;

/// <summary>
/// <c>pcporter selftest</c>: proves the parts that only fail inside the published single-file EXE
/// (native SQLite, crypto, WMI, shadow copies) actually work. Prints PASS / FAIL / SKIP per check.
/// </summary>
public static class SelfTestCommand
{
    public static Command Create(bool elevated)
    {
        var cmd = new Command("selftest", "Check that the database, encryption, WMI and shadow copies work on this PC");
        cmd.SetAction(_ =>
        {
            var temp = Directory.CreateTempSubdirectory("pcporter-selftest").FullName;
            int failures = 0;
            void Check(string name, Func<string?> test)
            {
                try
                {
                    var skip = test();
                    Console.WriteLine(skip is null ? $"PASS  {name}" : $"SKIP  {name} ({skip})");
                }
                catch (Exception ex) { failures++; Console.WriteLine($"FAIL  {name}: {ex.GetType().Name}: {ex.Message}"); }
            }

            Check("SQLite case database with full-text search", () =>
            {
                using var db = CaseDb.Open(Path.Combine(temp, "case.db"));
                db.Insert([new Artifact(DateTimeOffset.UtcNow, "Test", "selftest", "x", null, "Check", "pcporter-selftest-word", null, Confidence.Existed)]);
                if (db.Search("pcporter-selftest-word").Count != 1) throw new InvalidOperationException("search found nothing");
                return null;
            });

            Check("Encrypted vault round trip", () =>
            {
                var plain = new byte[1024]; Random.Shared.NextBytes(plain);
                using var a = new MemoryStream(plain); using var enc = new MemoryStream();
                VaultFile.Encrypt(a, enc, "selftest".ToCharArray(), new KdfParams(8 * 1024, 1, 1));
                enc.Position = 0; using var dec = new MemoryStream();
                VaultFile.Decrypt(enc, dec, "selftest".ToCharArray());
                if (!dec.ToArray().AsSpan().SequenceEqual(plain)) throw new InvalidOperationException("data changed");
                return null;
            });

            Check("Windows system query (WMI)", () =>
            {
                var r = new WmiClient().Query(@"root\cimv2", "SELECT Caption FROM Win32_OperatingSystem");
                if (r.Outcome != WmiOutcome.Ok || r.Rows.Count == 0) throw new InvalidOperationException(r.Outcome + " " + r.Message);
                return null;
            });

            Check("Shadow copy of a locked file", () =>
            {
                if (!elevated) return "needs administrator rights";
                var file = Path.Combine(Path.GetTempPath(), $"pcporter-selftest-{Guid.NewGuid():N}.txt");
                File.WriteAllText(file, "selftest");
                try
                {
                    using var locker = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    using var snap = new VssSnapshotProvider().Create(Path.GetPathRoot(file)!);
                    if (File.ReadAllText(snap.Map(file)) != "selftest") throw new InvalidOperationException("snapshot copy differs");
                    return null;
                }
                finally { File.Delete(file); }
            });

            try { Directory.Delete(temp, true); } catch (IOException) { }
            Console.WriteLine(failures == 0 ? "Self-test passed." : $"Self-test: {failures} check(s) failed.");
            return failures == 0 ? ExitCodes.Ok : ExitCodes.Failed;
        });
        return cmd;
    }
}
