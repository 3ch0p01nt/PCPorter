using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace PCPorter.Collectors.Posture;

/// <summary>Listening TCP sockets of this running PC (IPv4 and IPv6) via iphlpapi GetExtendedTcpTable. Read-only.</summary>
public static class TcpListeners
{
    const int AF_INET = 2, AF_INET6 = 23;
    const int TCP_TABLE_OWNER_PID_LISTENER = 3;
    const uint NO_ERROR = 0, ERROR_INSUFFICIENT_BUFFER = 122;
    const int Row4Size = 24;    // MIB_TCPROW_OWNER_PID
    const int Row6Size = 56;    // MIB_TCP6ROW_OWNER_PID

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, int ulAf, int tableClass, uint reserved);

    public static IReadOnlyList<PortListener> Read()
    {
        var names = new Dictionary<int, string?>();
        var list = new List<PortListener>();
        foreach (var (pid, address, port) in Rows(AF_INET).Concat(Rows(AF_INET6)))
        {
            if (!names.TryGetValue(pid, out var name)) names[pid] = name = ProcessName(pid);
            list.Add(new PortListener(address, port, pid, name));
        }
        return list;
    }

    static List<(int Pid, string Address, int Port)> Rows(int family)
    {
        var result = new List<(int, string, int)>();
        var bytes = Table(family);
        if (bytes.Length < 4) return result;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        int rowSize = family == AF_INET ? Row4Size : Row6Size;
        for (int i = 0; i < count; i++)
        {
            int o = 4 + i * rowSize;
            if (o + rowSize > bytes.Length) break;
            var r = bytes.AsSpan(o, rowSize);
            if (family == AF_INET)
            {
                // state, localAddr, localPort, remoteAddr, remotePort, owningPid
                var addr = new IPAddress(r.Slice(4, 4)).ToString();
                int port = (r[8] << 8) | r[9];
                int pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(r[20..]);
                result.Add((pid, addr, port));
            }
            else
            {
                // localAddr[16], localScopeId, localPort, remoteAddr[16], remoteScopeId, remotePort, state, owningPid
                var addr = new IPAddress(r[..16].ToArray()).ToString();
                int port = (r[20] << 8) | r[21];
                int pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(r[52..]);
                result.Add((pid, addr, port));
            }
        }
        return result;
    }

    static byte[] Table(int family)
    {
        int size = 0;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            var buffer = size > 0 ? Marshal.AllocHGlobal(size) : IntPtr.Zero;
            try
            {
                var rc = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
                if (rc == NO_ERROR && buffer != IntPtr.Zero)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buffer, bytes, 0, size);
                    return bytes;
                }
                if (rc != ERROR_INSUFFICIENT_BUFFER) throw new Win32Exception((int)rc);
                size += 1024;   // the table can grow between calls
            }
            finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
        }
        throw new Win32Exception((int)ERROR_INSUFFICIENT_BUFFER);
    }

    static string? ProcessName(int pid)
    {
        if (pid == 0) return "Idle";
        if (pid == 4) return "System";
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException) { return null; }
    }
}
