using System.Management;

namespace PCPorter.Collectors.Offline;

public enum UnlockOutcome { Unlocked, InvalidKeyFormat, WrongKey, AccessDenied, Failed }

public sealed record UnlockResult(UnlockOutcome Outcome, uint? ReturnValue, string Message);

/// <summary>
/// BitLocker unlock of another PC's drive with its 48-digit recovery key, via WMI in-process
/// (never a command line). The key is never logged, never put in a message, and the caller's char[] is wiped.
/// </summary>
public static class BitLocker
{
    public const string WhereToFindTheKey = "Find the recovery key at aka.ms/myrecoverykey (sign in with the old PC's Microsoft account), or ask your IT department.";

    const uint FVE_E_FAILED_AUTHENTICATION = 0x80310027;
    const uint E_ACCESSDENIED = 0x80070005;

    /// <summary>
    /// 8 groups of 6 digits separated by '-' (or 48 digits without separators). Each group must be divisible by 11
    /// and below 720896 (= 65536 * 11). Surrounding whitespace is ignored. Works on the span, no string copies.
    /// </summary>
    public static bool ValidateRecoveryKey(ReadOnlySpan<char> key)
    {
        key = key.Trim();
        bool dashed = key.Length == 8 * 6 + 7;
        if (!dashed && key.Length != 8 * 6) return false;
        int stride = dashed ? 7 : 6;
        for (int g = 0; g < 8; g++)
        {
            int start = g * stride;
            if (dashed && g < 7 && key[start + 6] != '-') return false;
            int value = 0;
            for (int i = 0; i < 6; i++)
            {
                char c = key[start + i];
                if (c is < '0' or > '9') return false;
                value = value * 10 + (c - '0');
            }
            if (value % 11 != 0 || value >= 720896) return false;
        }
        return true;
    }

    /// <summary>Unlocks the volume (Win32_EncryptableVolume.DeviceID). Always wipes <paramref name="recoveryKey"/>.</summary>
    public static UnlockResult Unlock(string deviceId, char[] recoveryKey)
    {
        try
        {
            if (!ValidateRecoveryKey(recoveryKey))
                return new UnlockResult(UnlockOutcome.InvalidKeyFormat, null, "That is not a valid recovery key: it has 8 groups of 6 digits. " + WhereToFindTheKey);

            using var volume = Volume(deviceId);
            using var inParams = volume.GetMethodParameters("UnlockWithNumericalPassword");
            inParams["NumericalPassword"] = new string(((ReadOnlySpan<char>)recoveryKey).Trim());
            using var outParams = volume.InvokeMethod("UnlockWithNumericalPassword", inParams, null);
            inParams["NumericalPassword"] = null;
            var rv = Convert.ToUInt32(outParams["ReturnValue"]);
            return rv switch
            {
                0 => new UnlockResult(UnlockOutcome.Unlocked, rv, "The drive is unlocked."),
                FVE_E_FAILED_AUTHENTICATION => new UnlockResult(UnlockOutcome.WrongKey, rv, "That recovery key does not unlock this drive. " + WhereToFindTheKey),
                E_ACCESSDENIED => new UnlockResult(UnlockOutcome.AccessDenied, rv, "Unlocking needs PCPorter to run as administrator."),
                _ => new UnlockResult(UnlockOutcome.Failed, rv, $"BitLocker could not unlock the drive (0x{rv:X8})."),
            };
        }
        catch (ManagementException e) when (e.ErrorCode == ManagementStatus.AccessDenied)
        {
            return new UnlockResult(UnlockOutcome.AccessDenied, null, "Unlocking needs PCPorter to run as administrator.");
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return new UnlockResult(UnlockOutcome.Failed, null, "BitLocker could not unlock the drive.");
        }
        finally
        {
            Array.Clear(recoveryKey);
        }
    }

    /// <summary>Locks the volume again after the scan (offered to the user).</summary>
    public static bool Lock(string deviceId)
    {
        try
        {
            using var volume = Volume(deviceId);
            using var inParams = volume.GetMethodParameters("Lock");
            inParams["ForceDismount"] = false;
            using var outParams = volume.InvokeMethod("Lock", inParams, null);
            return Convert.ToUInt32(outParams["ReturnValue"]) == 0;
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    static ManagementObject Volume(string deviceId)
    {
        var escaped = deviceId.Replace(@"\", @"\\", StringComparison.Ordinal).Replace("'", @"\'", StringComparison.Ordinal);
        var scope = new ManagementScope(OfflineVolumeFinder.BitLockerNamespace);
        return new ManagementObject(scope, new ManagementPath($"Win32_EncryptableVolume.DeviceID='{escaped}'"), null);
    }
}
