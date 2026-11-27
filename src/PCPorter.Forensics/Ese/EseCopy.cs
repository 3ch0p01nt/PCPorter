using System.Diagnostics;
using Microsoft.Isam.Esent;
using Microsoft.Isam.Esent.Interop;

namespace PCPorter.Forensics.Ese;

/// <summary>
/// Shared steps for reading a private copy of an ESE database (Windows search index, WebCache): a private engine instance
/// whose logs, checkpoint, temp database and recovery target are all the copy folder; log replay on the copy only; and
/// clean-up. Nothing here ever touches the original files.
/// </summary>
internal static class EseCopy
{
    static readonly TimeSpan EsentutlTimeout = TimeSpan.FromMinutes(10);

    /// <summary>A private ESE instance whose logs, checkpoint, temp database and recovery target are all the copy folder.</summary>
    public static Instance CreateInstance(string copy, string logBaseName, bool recovery, string displayName)
    {
        var dir = copy.TrimEnd('\\') + "\\";
        var instance = new Instance($"PCPorter-{Guid.NewGuid():N}", displayName);
        try
        {
            var p = instance.Parameters;
            p.SystemDirectory = dir;
            p.LogFileDirectory = dir;
            p.TempDirectory = dir;
            p.AlternateDatabaseRecoveryDirectory = dir;
            p.BaseName = logBaseName;
            p.Recovery = recovery;
            p.CreatePathIfNotExist = false;
            p.NoInformationEvent = true;
            p.EnableIndexChecking = false;
            // Existing logs must be replayed with their own size.
            var log = Path.Combine(copy, logBaseName + ".log");
            if (recovery && File.Exists(log)) p.LogFileSize = (int)(new FileInfo(log).Length / 1024);
            return instance;
        }
        catch
        {
            instance.Dispose();
            throw;
        }
    }

    /// <summary>Database page size is process-wide in ESE and must match the file before JetInit.</summary>
    public static void SetPageSize(int pageSize)
    {
        if (pageSize <= 0) return;
        try
        {
            if (SystemParameters.DatabasePageSize != pageSize) SystemParameters.DatabasePageSize = pageSize;
        }
        catch (EsentException)
        {
            // Another ESE instance in this process already fixed the page size; attach will report a mismatch.
        }
    }

    public static bool IsClean(string db)
    {
        try
        {
            Api.JetGetDatabaseFileInfo(db, out JET_DBINFOMISC info, JET_DbInfo.Misc);
            return info.dbstate == JET_dbstate.CleanShutdown;
        }
        catch (EsentException) { return false; }
    }

    /// <summary>Replays the copied logs with the engine in-process. Returns an error message, or null when it ran without one.</summary>
    public static string? RecoverWithEngine(string copy, string logBaseName, string displayName)
    {
        try
        {
            using var instance = CreateInstance(copy, logBaseName, recovery: true, displayName);
            instance.Init();
            return null;
        }
        catch (EsentException ex) { return ex.Message; }
    }

    /// <summary>Runs esentutl soft recovery against the copy. Returns an error message, or null on exit code 0.</summary>
    public static string? RunEsentutl(string copy, string logBaseName)
    {
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "esentutl.exe");
        if (!File.Exists(exe)) return "esentutl.exe was not found";
        var dir = copy.TrimEnd('\\') + "\\";
        var psi = new ProcessStartInfo(exe)
        {
            WorkingDirectory = copy,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[] { "/r", logBaseName, "/l" + dir, "/s" + dir, "/d" + dir, "/o" }) psi.ArgumentList.Add(arg);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("esentutl could not be started");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(EsentutlTimeout))
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            return "esentutl timed out";
        }
        p.WaitForExit();
        if (p.ExitCode == 0) return null;
        var text = (stdout.Result + stderr.Result).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return $"esentutl exit code {p.ExitCode}" + (text.Length > 0 ? $": {text[^1]}" : "");
    }

    public static void TryDeleteFolder(string folder)
    {
        try
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: the work folder is the caller's scratch area.
        }
    }
}
