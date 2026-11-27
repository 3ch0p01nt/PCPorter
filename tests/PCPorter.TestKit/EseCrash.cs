using System.Diagnostics;
using Microsoft.Isam.Esent.Interop;

namespace PCPorter.TestKit;

/// <summary>
/// Leaves an ESE database in dirty-shutdown state the way a crash (or a copy of a database in use) does: Windows
/// PowerShell P/Invokes esent.dll, attaches the database and kills itself without JetTerm, so log replay is needed.
/// </summary>
public static class EseCrash
{
    /// <returns>The helper's output: the JET return codes, comma separated (all 0 or positive on success).</returns>
    public static string WhileAttached(string folder, string logBaseName, string databaseFileName)
    {
        Api.JetGetDatabaseFileInfo(Path.Combine(folder, databaseFileName), out int pageSize, JET_DbInfo.PageSize);
        const string Script = """
            param($dir, $pageSize, $base, $file)
            Add-Type -TypeDefinition @'
            using System; using System.Runtime.InteropServices;
            public static class J {
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetCreateInstanceW(out IntPtr i, string n);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetSetSystemParameterW(ref IntPtr i, IntPtr s, int p, IntPtr l, string v);
              [DllImport("esent.dll")] public static extern int JetInit(ref IntPtr i);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetBeginSessionW(IntPtr i, out IntPtr s, string u, string p);
              [DllImport("esent.dll", CharSet = CharSet.Unicode)] public static extern int JetAttachDatabaseW(IntPtr s, string f, int g);
            }
            '@
            $i = [IntPtr]::Zero; $s = [IntPtr]::Zero; $z = [IntPtr]::Zero
            $rc = @()
            $rc += [J]::JetSetSystemParameterW([ref]$z, $z, 64, [IntPtr][int]$pageSize, $null)
            $rc += [J]::JetCreateInstanceW([ref]$i, 'pcporter-crash')
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 0, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 1, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 2, $z, "$dir\")
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 3, $z, $base)
            $rc += [J]::JetSetSystemParameterW([ref]$i, $z, 11, [IntPtr]1024, $null)
            $rc += [J]::JetInit([ref]$i)
            $rc += [J]::JetBeginSessionW($i, [ref]$s, '', '')
            $rc += [J]::JetAttachDatabaseW($s, "$dir\$file", 0)
            [Console]::Out.WriteLine(($rc -join ','))
            [Console]::Out.Flush()
            [Diagnostics.Process]::GetCurrentProcess().Kill()
            """;
        var scriptFolder = Directory.CreateTempSubdirectory("pcporter-esecrash").FullName;
        try
        {
            var scriptPath = Path.Combine(scriptFolder, "crash.ps1");
            File.WriteAllText(scriptPath, Script);
            var psi = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"))
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, folder.TrimEnd('\\'), pageSize.ToString(), logBaseName, databaseFileName })
                psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(60_000)) throw new TimeoutException("ESE crash helper hung");
            return output.Trim();
        }
        finally
        {
            try { Directory.Delete(scriptFolder, true); } catch (IOException) { }
        }
    }
}
