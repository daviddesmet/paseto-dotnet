namespace Paseto;

/// <summary>
/// Trait RegisteredClaims.
/// Adopted from JWT for usability.
/// </summary>
public static class PasetoRegisteredClaimNames
{
    public const string Issuer = "iss";

    public const string Subject = "sub";

    public const string Audience = "aud";

    public const string ExpirationTime = "exp";

    public const string NotBefore = "nbf";

    public const string IssuedAt = "iat";

    public const string TokenIdentifier = "jti";
}