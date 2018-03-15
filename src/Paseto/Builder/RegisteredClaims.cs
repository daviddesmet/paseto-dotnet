namespace Paseto.Builder
{
    using System.ComponentModel;

    /// <summary>
    /// Trait RegisteredClaims.
    /// Adopted from JWT for usability.
    /// </summary>
    public enum RegisteredClaims
    {
        [Description("iss")]
        Issuer,

        [Description("sub")]
        Subject,

        [Description("aud")]
        Audience,

        [Description("exp")]
        ExpirationTime,

        [Description("nbf")]
        NotBefore,

        [Description("iat")]
        IssuedAt
    }
}
