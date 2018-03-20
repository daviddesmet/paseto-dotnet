namespace Paseto.Builder
{
    using System;

    using Protocol;
    using Utils;

    public static class PasetoBuilderExtensions
    {
        /// <summary>
        /// Adds an issuer claim to the Paseto.
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> Issuer<TProtocol>(this PasetoBuilder<TProtocol> builder, string issuer) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Issuer, issuer);

        /// <summary>
        /// Adds a subject claim to the Paseto.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> Subject<TProtocol>(this PasetoBuilder<TProtocol> builder, string subject) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Subject, subject);

        /// <summary>
        /// Adds an audience claim to the Paseto.
        /// </summary>
        /// <param name="audience">The audience.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> Audience<TProtocol>(this PasetoBuilder<TProtocol> builder, string audience) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Audience, audience);

        /// <summary>
        /// Adds an expiration claim to the Paseto.
        /// </summary>
        /// <param name="time">The Utc time.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> Expiration<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.ExpirationTime, UnixEpoch.ToUnixTimeString(time));

        /// <summary>
        /// Adds a not before claim to the Paseto.
        /// </summary>
        /// <param name="time">The Utc time.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> NotBefore<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.NotBefore, UnixEpoch.ToUnixTimeString(time));

        /// <summary>
        /// Adds an issued claim to the Paseto.
        /// </summary>
        /// <param name="time">The Utc time.</param>
        /// <returns>Current builder instance</returns>
        public static PasetoBuilder<TProtocol> IssuedAt<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.IssuedAt, UnixEpoch.ToUnixTimeString(time));
    }
}
