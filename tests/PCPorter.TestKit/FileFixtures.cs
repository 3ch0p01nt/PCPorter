using System.Text;

namespace PCPorter.TestKit;

/// <summary>Writes a minimal binary .lnk (header + LinkInfo with a local base path), as Windows stores it.</summary>
public static class TestLnk
{
    public static void Write(string path, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        // ShellLinkHeader (76 bytes)
        w.Write(0x4C);
        w.Write(new Guid("00021401-0000-0000-C000-000000000046").ToByteArray());
        w.Write(0x02);                 // HasLinkInfo
        w.Write(0x20);                 // FILE_ATTRIBUTE_ARCHIVE
        w.Write(0L); w.Write(0L); w.Write(0L);
        w.Write(0); w.Write(0); w.Write(1);
        w.Write((short)0); w.Write((short)0); w.Write(0); w.Write(0);
        // LinkInfo
        var basePath = Encoding.ASCII.GetBytes(target + "\0");
        const int headerSize = 0x1C, volumeIdSize = 0x11;
        int localBaseOffset = headerSize + volumeIdSize;
        int suffixOffset = localBaseOffset + basePath.Length;
        int linkInfoSize = suffixOffset + 1;
        w.Write(linkInfoSize); w.Write(headerSize); w.Write(1);          // VolumeIDAndLocalBasePath
        w.Write(headerSize); w.Write(localBaseOffset); w.Write(0); w.Write(suffixOffset);
        w.Write(volumeIdSize); w.Write(3); w.Write(0x1234ABCD); w.Write(0x10); w.Write((byte)0);   // VolumeID, empty label
        w.Write(basePath);
        w.Write((byte)0);              // empty common path suffix
        w.Write(0);                    // terminal extra-data block
        w.Flush();
        File.WriteAllBytes(path, ms.ToArray());
    }
}

/// <summary>Scheduled-task XML files as Windows writes them under Windows\System32\Tasks.</summary>
public static class TaskXml
{
    /// <summary>Writes a byte-for-byte Windows-style task file: UTF-16 LE with BOM.</summary>
    public static void Write(string tasksRoot, string taskPath, string actionsXml, bool enabled = true)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windowstask/2004/02/mit/task">
              <RegistrationInfo>
                <Author>Test</Author>
                <URI>{taskPath}</URI>
              </RegistrationInfo>
              <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
              <Settings>
                <Enabled>{(enabled ? "true" : "false")}</Enabled>
                <Hidden>false</Hidden>
              </Settings>
              <Actions Context="Author">
            {actionsXml}
              </Actions>
            </Task>
            """;
        var file = Path.Combine(tasksRoot, taskPath.TrimStart('\\'));
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, xml, new System.Text.UnicodeEncoding(bigEndian: false, byteOrderMark: true));
    }

    public static string Exec(string command, string? args = null) =>
        $"    <Exec><Command>{System.Security.SecurityElement.Escape(command)}</Command>{(args is null ? "" : $"<Arguments>{System.Security.SecurityElement.Escape(args)}</Arguments>")}</Exec>";
}
