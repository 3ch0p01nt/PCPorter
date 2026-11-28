using System.Diagnostics;
using System.Globalization;
using PCPorter.Core.IO;

namespace PCPorter.Core.Tests.IO;

public class FileIdentityTests
{
    [Fact]
    public void Identity_reads_the_real_volume_serial_and_file_index()
    {
        var file = Path.GetTempFileName();
        try
        {
            var id = FileIdentity.Identity(file);
            Assert.NotNull(id);
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/c vol {Path.GetPathRoot(file)![..2]}")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true })!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            var serial = output.Split(' ', '\r', '\n').Last(s => s.Length == 9 && s[4] == '-');      // "1234-ABCD" (any UI language)
            Assert.Equal(uint.Parse(serial.Replace("-", ""), NumberStyles.HexNumber, CultureInfo.InvariantCulture), id!.Value.Volume);
            Assert.NotEqual(id, FileIdentity.Identity(Path.GetTempPath()));
            Assert.Equal(id, FileIdentity.Identity(@"\\?\" + file));

            using var fs = File.OpenRead(file);
            Assert.Equal(1u, FileIdentity.LinkCount(fs.SafeFileHandle));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void Entry_falls_back_to_plain_attributes_on_drives_without_reparse_tags()
    {
        // exFAT and FAT32 (most USB backup drives) do not answer FileAttributeTagInfo: the folder must still be usable.
        var folder = FileIdentity.EntryFromAttributesOnly((uint)FileAttributes.Directory);
        Assert.False(folder.IsReparsePoint);
        Assert.False(folder.IsLink);
        Assert.False(folder.IsCloud);

        // A reparse point whose tag cannot be read is treated as a link (fail closed), never as a normal folder.
        var unknown = FileIdentity.EntryFromAttributesOnly((uint)(FileAttributes.Directory | FileAttributes.ReparsePoint));
        Assert.True(unknown.IsLink);

        // Cloud placeholder attributes still count without a tag.
        Assert.True(FileIdentity.EntryFromAttributesOnly((uint)FileAttributes.Directory | 0x400000).IsCloud);
    }

    [Fact]
    public void Entry_describes_the_link_itself()
    {
        var root = Directory.CreateTempSubdirectory("pcporter-entry").FullName;
        var link = Path.Combine(root, "link");
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(root, "target")).FullName;
            Case.CaseLocationTests.Junction(link, target);
            var e = FileIdentity.Entry(link)!.Value;
            Assert.True(e.IsLink);
            Assert.False(e.IsCloud);
            Assert.False(FileIdentity.Entry(target)!.Value.IsReparsePoint);
            Assert.Null(FileIdentity.Entry(Path.Combine(root, "missing")));
            Assert.Equal(FileIdentity.NtPath(target), FileIdentity.NtPath(link));
        }
        finally { if (Directory.Exists(link)) Directory.Delete(link); Directory.Delete(root, true); }
    }
}
