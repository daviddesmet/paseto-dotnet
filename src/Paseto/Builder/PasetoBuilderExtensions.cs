namespace Paseto.Builder;

using System;

public static class PasetoBuilderExtensions
{
    //public const string DateTimeISO8601Format = "yyyy-MM-ddTHH:mm:sszzz"; // The default format used by Json.NET is the ISO 8601 standard

    /// <summary>
    /// Adds an issuer claim to the Paseto.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder Issuer(this PasetoBuilder builder, string issuer) => builder.AddClaim(RegisteredClaims.Issuer, issuer);

    /// <summary>
    /// Adds a subject claim to the Paseto.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder Subject(this PasetoBuilder builder, string subject) => builder.AddClaim(RegisteredClaims.Subject, subject);

    /// <summary>
    /// Adds an audience claim to the Paseto.
    /// </summary>
    /// <param name="audience">The audience.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder Audience(this PasetoBuilder builder, string audience) => builder.AddClaim(RegisteredClaims.Audience, audience);

    /// <summary>
    /// Adds an expiration claim to the Paseto.
    /// The Utc time will be converted to Unix time.
    /// </summary>
    /// <param name="time">The Utc time.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder Expiration(this PasetoBuilder builder, DateTime time) => builder.AddClaim(RegisteredClaims.ExpirationTime, time);

    /// <summary>
    /// Adds a not before claim to the Paseto.
    /// The Utc time will be converted to Unix time.
    /// </summary>
    /// <param name="time">The Utc time.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder NotBefore(this PasetoBuilder builder, DateTime time) => builder.AddClaim(RegisteredClaims.NotBefore, time);

    /// <summary>
    /// Adds an issued claim to the Paseto.
    /// The Utc time will be converted to Unix time.
    /// </summary>
    /// <param name="time">The Utc time.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder IssuedAt(this PasetoBuilder builder, DateTime time) => builder.AddClaim(RegisteredClaims.IssuedAt, time);

    /// <summary>
    /// Adds a token identifier claim to the Paseto.
    /// </summary>
    /// <param name="jti">The token identifier.</param>
    /// <returns>Current builder instance</returns>
    public static PasetoBuilder TokenIdentifier(this PasetoBuilder builder, string jti) => builder.AddClaim(RegisteredClaims.TokenIdentifier, jti);
}
