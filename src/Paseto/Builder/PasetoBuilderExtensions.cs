namespace Paseto.Builder
{
    using System;

    using Protocol;
    using Utils;

    public static class PasetoBuilderExtensions
    {
        public static PasetoBuilder<TProtocol> Issuer<TProtocol>(this PasetoBuilder<TProtocol> builder, string issuer) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Issuer, issuer);

        public static PasetoBuilder<TProtocol> Subject<TProtocol>(this PasetoBuilder<TProtocol> builder, string subject) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Subject, subject);

        public static PasetoBuilder<TProtocol> Audience<TProtocol>(this PasetoBuilder<TProtocol> builder, string audience) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.Audience, audience);

        public static PasetoBuilder<TProtocol> Expiration<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.ExpirationTime, UnixEpoch.ToUnixTimeString(time));

        public static PasetoBuilder<TProtocol> NotBefore<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.NotBefore, UnixEpoch.ToUnixTimeString(time));

        public static PasetoBuilder<TProtocol> IssuedAt<TProtocol>(this PasetoBuilder<TProtocol> builder, DateTime time) where TProtocol : IPasetoProtocol, new() => builder.AddClaim(RegisteredClaims.IssuedAt, UnixEpoch.ToUnixTimeString(time));
    }
}
