using System.Text.RegularExpressions;
using PCPorter.Core.Security;

namespace PCPorter.Forensics.BrowserHistory;

/// <summary>
/// The privacy filter for saved form entries (Chromium autofill, Firefox form history): fields whose name looks like a
/// password, card, PIN, SSN, IBAN or account number are dropped, as are values that look like a payment card number.
/// Everything kept goes through <see cref="Redactor"/>.
/// </summary>
public static partial class FormFields
{
    [GeneratedRegex("pass|pwd|card|cc-?num|cvv|cvc|pin|ssn|iban|account|routing|secret|token|otp", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveName();

    public static bool IsSensitiveField(string field) => SensitiveName().IsMatch(field);

    /// <summary>13 to 19 digits (spaces and dashes allowed) that pass the Luhn check.</summary>
    public static bool LooksLikeCardNumber(string value)
    {
        Span<int> digits = stackalloc int[19];
        int n = 0;
        foreach (var c in value.Trim())
        {
            if (c is ' ' or '-') continue;
            if (c is < '0' or > '9' || n == 19) return false;
            digits[n++] = c - '0';
        }
        if (n < 13) return false;
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            int d = digits[n - 1 - i];
            if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
        }
        return sum % 10 == 0;
    }

    /// <summary>A form entry with masked value, or null when the field or value must not be shown.</summary>
    public static FormEntry? Make(BrowserProfile profile, string? field, string? value, long count, DateTimeOffset? first, DateTimeOffset? last)
    {
        if (string.IsNullOrWhiteSpace(field) || value is null || IsSensitiveField(field) || LooksLikeCardNumber(value)) return null;
        return new FormEntry(profile, Redactor.Redact(field), Redactor.Redact(value), (int)Math.Clamp(count, 0, int.MaxValue), first, last);
    }

    public static string DroppedNote(BrowserProfile profile, int dropped) =>
        $"{dropped} saved form entr{(dropped == 1 ? "y" : "ies")} in {profile.Browser} ({profile.Name}) for {profile.User} " +
        $"{(dropped == 1 ? "was" : "were")} left out because the field looks like a password, card, PIN or account number.";
}
