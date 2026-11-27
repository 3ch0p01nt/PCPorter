using System.Buffers.Binary;
using System.Text;
using PCPorter.Collectors.Persistence;
using PCPorter.TestKit;

namespace PCPorter.Collectors.Tests.Persistence;

public class TaskPersistenceTests : IDisposable
{
    readonly string _root = Directory.CreateTempSubdirectory("pcporter-tasks").FullName;
    readonly string _tasks;
    public TaskPersistenceTests() => _tasks = Directory.CreateDirectory(Path.Combine(_root, "Windows", "System32", "Tasks")).FullName;
    public void Dispose() => Directory.Delete(_root, true);

    const string TaskCache = @"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
    const string ComClsid = "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}";

    static byte[] Blob(params (string Command, string Args)[] execs)
    {
        using var ms = new MemoryStream();
        void U16(ushort v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, v); ms.Write(b); }
        void Str(string v) { var bytes = Encoding.Unicode.GetBytes(v); var b = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(b, bytes.Length); ms.Write(b); ms.Write(bytes); }
        U16(3); Str("Author");
        foreach (var (c, a) in execs) { U16(0x6666); Str(""); Str(c); Str(a); Str(""); U16(0); }
        return ms.ToArray();
    }

    void Fixtures()
    {
        P.WriteTask(_tasks, @"\Microsoft\Windows\Defrag\ScheduledDefrag", P.Exec(@"%windir%\system32\defrag.exe", "-c -h -o -$"));
        P.WriteTask(_tasks, @"\MultiAction", P.Exec(@"C:\Tools\one.exe") + "\n" + P.Exec(@"C:\Tools\two.exe", "/x"));
        P.WriteTask(_tasks, @"\Microsoft\Windows\Com\ComOnly", $"    <ComHandler><ClassId>{ComClsid}</ClassId><Data>x</Data></ComHandler>");
        P.WriteTask(_tasks, @"\QuotedApp", P.Exec(@"""C:\Program Files\App\app.exe""", "--background --flag"));
        P.WriteTask(_tasks, @"\UnquotedSpaces", P.Exec(@"C:\Program Files\App\app.exe", "--x"));
        P.WriteTask(_tasks, @"\DisabledTask", P.Exec(@"C:\Users\Public\off.exe"), enabled: false);
        P.WriteTask(_tasks, @"\Microsoft\Windows\WindowsUpdate\Updater", P.Exec(@"C:\Users\Public\Libraries\upd.exe"));
        P.WriteTask(_tasks, @"\NoSd", P.Exec(@"C:\Windows\System32\cmd.exe", "/c echo"));
    }

    RegSpec Software() => RegSpec.Root()
        .Key($@"Classes\CLSID\{ComClsid}\InprocServer32", k => k.Exp("", @"%SystemRoot%\System32\dsregcmd.dll"))
        .Key(TaskCache + @"\Tree\Microsoft\Windows\Defrag\ScheduledDefrag", k => k.Str("Id", "{A}").Bin("SD", 1, 2, 3))
        .Key(TaskCache + @"\Tree\NoSd", k => k.Str("Id", "{N}"))
        .Key(TaskCache + @"\Tree\Ghost", k => k.Str("Id", "{G}").Bin("SD", 1, 2, 3))
        .Key(TaskCache + @"\Tasks\{G}", k => k.Str("Path", @"\Ghost").Bin("Actions", Blob((@"C:\ProgramData\g.exe", "-q"))));

    List<PersistenceEntry> Read() => TaskPersistence.Read(new FakeSystemSource(_root, Software()), new List<string>()).ToList();

    [Fact]
    public void Task_files_are_real_utf16_le_with_bom()
    {
        Fixtures();
        var bytes = File.ReadAllBytes(Path.Combine(_tasks, "MultiAction"));
        Assert.Equal([0xFF, 0xFE], bytes[..2]);
        Assert.Equal((byte)'<', bytes[2]);
        Assert.Equal(0, bytes[3]);
    }

    [Fact]
    public void Parses_namespace_and_percent_windir_command()
    {
        Fixtures();
        var e = Assert.Single(Read(), x => x.Name == "ScheduledDefrag");
        Assert.Equal(@"Task Scheduler\Microsoft\Windows\Defrag", e.Location);
        Assert.Equal(@"%windir%\system32\defrag.exe -c -h -o -$", e.Command);
        Assert.False(e.TaskHidden);
        using var src = new FakeSystemSource(_root, Software());
        var item = PersistenceCollector.Evaluate(e, src, FakeSignatures.WindowsIsMicrosoft());
        Assert.Equal(@"C:\Windows\system32\defrag.exe", item.ImagePath);
        Assert.True(item.IsHidden);
    }

    [Fact]
    public void Multiple_exec_actions_become_separate_entries()
    {
        Fixtures();
        var multi = Read().Where(x => x.Name.StartsWith("MultiAction")).OrderBy(x => x.Name).ToList();
        Assert.Equal(["MultiAction (action 1)", "MultiAction (action 2)"], multi.Select(m => m.Name));
        Assert.Equal(@"C:\Tools\two.exe /x", multi[1].Command);
    }

    [Fact]
    public void ComHandler_is_resolved_through_InprocServer32()
    {
        Fixtures();
        var e = Assert.Single(Read(), x => x.Name == "ComOnly");
        Assert.Equal(@"%SystemRoot%\System32\dsregcmd.dll", e.Command);
        Assert.Contains(ComClsid, e.Note);
        Assert.Equal(@"%SystemRoot%\System32\dsregcmd.dll", TaskPersistence.ResolveClsid(Software().ToFake().Open(@"Classes\CLSID"), ComClsid));
    }

    [Fact]
    public void Quoted_and_unquoted_commands_with_arguments()
    {
        Fixtures();
        var entries = Read();
        var q = PersistenceCollector.Evaluate(entries.Single(x => x.Name == "QuotedApp"), new FakeSystemSource(_root), new NoSignatureChecker());
        Assert.Equal(@"C:\Program Files\App\app.exe", q.ImagePath);
        Assert.Equal(@"""C:\Program Files\App\app.exe"" --background --flag", q.Command);
        // Task Scheduler treats <Command> as one path, so an unquoted one with spaces is quoted for parsing.
        Assert.Equal(@"""C:\Program Files\App\app.exe"" --x", entries.Single(x => x.Name == "UnquotedSpaces").Command);
    }

    [Fact]
    public void Disabled_task_is_marked_and_downgraded()
    {
        Fixtures();
        var e = Assert.Single(Read(), x => x.Name == "DisabledTask");
        Assert.True(e.Disabled);
        var item = PersistenceCollector.Evaluate(e, new FakeSystemSource(_root), new FakeSignatures(_ => FakeSignatures.Unsigned));
        Assert.Equal("UNSIGNED_RISKY_PATH", item.RuleId);
        Assert.Equal(Severity.Medium, item.Severity);
        Assert.True(item.Disabled);
    }

    [Fact]
    public void Non_microsoft_exe_hidden_in_the_microsoft_tree_is_flagged()
    {
        Fixtures();
        var src = new FakeSystemSource(_root, Software());
        var output = new PersistenceCollector().Run(P.Context(src, FakeSignatures.WindowsIsMicrosoft()), CancellationToken.None);
        var items = P.Items(output);
        var evil = Assert.Single(items, i => i.Name == "Updater");
        Assert.Equal(@"Task Scheduler\Microsoft\Windows\WindowsUpdate", evil.Location);
        Assert.Equal(Severity.High, evil.Severity);
        Assert.False(evil.IsHidden);
        Assert.True(items.Single(i => i.Name == "ScheduledDefrag").IsHidden);
    }

    [Fact]
    public void TaskCache_only_task_is_hidden_and_its_action_decoded()
    {
        Fixtures();
        var ghost = Assert.Single(Read(), x => x.Name == "Ghost");
        Assert.True(ghost.TaskHidden);
        Assert.Equal(@"C:\ProgramData\g.exe -q", ghost.Command);
        var item = PersistenceCollector.Evaluate(ghost, new FakeSystemSource(_root), FakeSignatures.WindowsIsMicrosoft());
        Assert.Equal("TASK_HIDDEN", item.RuleId);
        Assert.Equal(Severity.High, item.Severity);
    }

    [Fact]
    public void Task_without_security_descriptor_is_hidden()
    {
        Fixtures();
        var e = Assert.Single(Read(), x => x.Name == "NoSd");
        Assert.True(e.TaskHidden);
        Assert.Equal("TASK_HIDDEN", PersistenceCollector.Evaluate(e, new FakeSystemSource(_root), FakeSignatures.WindowsIsMicrosoft()).RuleId);
    }

    [Fact]
    public void Broken_task_file_is_a_warning()
    {
        File.WriteAllText(Path.Combine(_tasks, "Broken"), "<Task><not closed", Encoding.Unicode);
        var warnings = new List<string>();
        var entries = TaskPersistence.Read(new FakeSystemSource(_root, RegSpec.Root()), warnings);
        Assert.Empty(entries);
        Assert.Single(warnings);
    }

    [Fact]
    public void Garbage_actions_blob_decodes_to_nothing() =>
        Assert.Empty(TaskPersistence.ParseActionsBlob([3, 0, 0xFF, 0xFF, 0xFF, 0x7F]));
}
