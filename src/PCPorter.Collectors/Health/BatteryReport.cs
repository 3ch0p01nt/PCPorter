using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using PCPorter.Collectors.Sources;

namespace PCPorter.Collectors.Health;

/// <summary>Battery health from <c>powercfg /batteryreport /xml</c> (live), with a WMI fallback.</summary>
public static class BatteryReport
{
    public static readonly XNamespace Ns = "http://schemas.microsoft.com/battery/2012";
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>Null = no battery (desktop) or nothing readable.</summary>
    public static IReadOnlyList<BatteryInfo>? Read(IProcessRunner processes, IWmiClient wmi, string workFolder, IList<string> warnings, IDictionary<string, string> unknown)
    {
        var output = Path.Combine(workFolder, "battery.xml");
        try
        {
            Directory.CreateDirectory(workFolder);
            if (File.Exists(output)) File.Delete(output);
            var r = processes.Run("powercfg.exe", ["/batteryreport", "/xml", "/output", output], Timeout);
            if (r.TimedOut) warnings.Add("Profile: battery report timed out.");
            else if (File.Exists(output))
            {
                string xml;
                using (var fs = SourceFiles.OpenRead(output))
                using (var sr = new StreamReader(fs))
                    xml = sr.ReadToEnd();
                return Parse(xml);
            }
            else warnings.Add($"Profile: battery report was not written (exit code {r.ExitCode}).");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or XmlException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            warnings.Add($"Profile: battery report failed: {e.Message}");
        }
        finally
        {
            // The report contains battery serial numbers; we keep only the parsed fields.
            try { if (File.Exists(output)) File.Delete(output); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return FromWmi(wmi, unknown);
    }

    /// <summary>Parses a powercfg battery report. Empty Batteries element (desktop) => null.</summary>
    public static IReadOnlyList<BatteryInfo>? Parse(string xml)
    {
        var doc = XDocument.Parse(xml, LoadOptions.None);
        var batteries = doc.Root?.Element(Ns + "Batteries")?.Elements(Ns + "Battery").ToList();
        if (batteries is null || batteries.Count == 0) return null;
        return batteries.Select(b =>
        {
            var design = Long(b, "DesignCapacity");
            var full = Long(b, "FullChargeCapacity");
            var cycles = Long(b, "CycleCount");
            return new BatteryInfo(Text(b, "Id"), Text(b, "Manufacturer"), Text(b, "Chemistry"), design, full,
                cycles is > 0 and <= int.MaxValue ? (int)cycles : null, Health(design, full));
        }).ToList();
    }

    /// <summary>Full / design as a percentage, clamped to 100; null when either is missing or zero.</summary>
    public static int? Health(long? design, long? full)
    {
        if (design is not > 0 || full is not > 0) return null;
        var pct = (int)Math.Round(full.Value * 100.0 / design.Value, MidpointRounding.AwayFromZero);
        return Math.Min(pct, 100);
    }

    static string? Text(XElement b, string name) => b.Element(Ns + name)?.Value.Trim() is { Length: > 0 } s ? s : null;
    static long? Long(XElement b, string name) => long.TryParse(Text(b, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;

    /// <summary>root\wmi BatteryStaticData + BatteryFullChargedCapacity, paired by order.</summary>
    static IReadOnlyList<BatteryInfo>? FromWmi(IWmiClient wmi, IDictionary<string, string> unknown)
    {
        try
        {
            var stat = wmi.Query(WmiProfile.WmiNs, "SELECT DesignedCapacity, ManufactureName, DeviceName FROM BatteryStaticData");
            if (stat.Outcome == WmiOutcome.AccessDenied) { unknown["batteries"] = PcProfile.NotElevated; return null; }
            if (stat.Outcome != WmiOutcome.Ok || stat.Rows.Count == 0) return null;
            var full = wmi.Query(WmiProfile.WmiNs, "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity");
            var fullRows = full.Outcome == WmiOutcome.Ok ? full.Rows : [];
            return stat.Rows.Select((r, i) =>
            {
                var d = WmiValue.Long(r, "DesignedCapacity");
                var f = i < fullRows.Count ? WmiValue.Long(fullRows[i], "FullChargedCapacity") : null;
                return new BatteryInfo(WmiValue.Str(r, "DeviceName"), WmiValue.Str(r, "ManufactureName"), null, d, f, null, Health(d, f));
            }).ToList();
        }
        catch (Exception) { return null; }
    }
}
