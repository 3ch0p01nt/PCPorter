namespace PCPorter.Collectors.Signing;

/// <summary>What a WinVerifyTrust result means for us.</summary>
public enum TrustOutcome
{
    /// <summary>Signature present and trusted.</summary>
    Valid,
    /// <summary>No embedded signature (or a file type WinTrust cannot sign) - the catalog check may still find it.</summary>
    NotEmbedded,
    /// <summary>A signature is present but must not be trusted (tampered, untrusted root, revoked, expired...).</summary>
    Invalid,
    /// <summary>Anything else (file unreadable, provider error): the signature was not checked.</summary>
    Unknown,
}

/// <summary>Maps WinVerifyTrust HRESULTs (pure, unit-tested).</summary>
public static class HResultMapper
{
    public const int S_OK = 0;
    public const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    public const int TRUST_E_ACTION_UNKNOWN = unchecked((int)0x800B0002);
    public const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    public const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    public const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    public const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    public const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    public const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    public const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    public const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110);
    public const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    public const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);
    public const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    public const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);
    public const int CRYPT_E_REVOKED = unchecked((int)0x80092010);
    public const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

    public static TrustOutcome Map(int hresult) => hresult switch
    {
        S_OK => TrustOutcome.Valid,
        TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => TrustOutcome.NotEmbedded,
        TRUST_E_BAD_DIGEST or CERT_E_UNTRUSTEDROOT or CERT_E_REVOKED or CRYPT_E_REVOKED or TRUST_E_EXPLICIT_DISTRUST
            or CERT_E_EXPIRED or CRYPT_E_SECURITY_SETTINGS or TRUST_E_SUBJECT_NOT_TRUSTED
            or CERT_E_CHAINING or TRUST_E_CERT_SIGNATURE or CERT_E_WRONG_USAGE => TrustOutcome.Invalid,
        _ => TrustOutcome.Unknown,
    };
}
