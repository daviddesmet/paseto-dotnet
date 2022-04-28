using System.ComponentModel;
using System.Linq;
using FluentAssertions;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Xunit;

namespace Paseto.Tests
{
    public sealed class PasetoValidationTest
    {
        [Theory(DisplayName = "Should succeed on token with valid issuer")]
        [InlineData(ProtocolVersion.V3, Purpose.Local)]
        [InlineData(ProtocolVersion.V3, Purpose.Public)]
        [InlineData(ProtocolVersion.V4, Purpose.Local)]
        [InlineData(ProtocolVersion.V4, Purpose.Public)]
        public void TokenWithValidIssuerValidationSucceeds(ProtocolVersion version, Purpose purpose)
        {
            var validationParameters = new PasetoTokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = "valid-issuer",
            };

            var (token, decodeKey) = GenerateToken(version, purpose, "valid-issuer");
            var decoded = new PasetoBuilder()
                .Use(version, purpose)
                .WithKey(decodeKey)
                .Decode(token, validationParameters);

            decoded.IsValid.Should().BeTrue();
        }

        [Theory(DisplayName = "Should fail on token with invalid issuer")]
        [InlineData(ProtocolVersion.V3, Purpose.Local)]
        [InlineData(ProtocolVersion.V3, Purpose.Public)]
        [InlineData(ProtocolVersion.V4, Purpose.Local)]
        [InlineData(ProtocolVersion.V4, Purpose.Public)]
        public void TokenWithInValidIssuerValidationFails(ProtocolVersion version, Purpose purpose)
        {
            var validationParameters = new PasetoTokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = "valid-issuer",
            };

            var (token, decodeKey) = GenerateToken(version, purpose, "invalid-issuer");
            var decoded = new PasetoBuilder()
                .Use(version, purpose)
                .WithKey(decodeKey)
                .Decode(token, validationParameters);

            decoded.IsValid.Should().BeFalse();
        }

        private static (string token, PasetoKey decodeKey) GenerateToken(ProtocolVersion version, Purpose purpose, string issuer)
        {
            var builder = new PasetoBuilder().Use(version, purpose);
            switch (purpose)
            {
                case Purpose.Local:
                {
                    var key = builder.GenerateSymmetricKey();
                    var token = builder
                        .WithKey(key)
                        .Issuer(issuer)
                        .Encode();
                    return (token, key);
                }
                case Purpose.Public:
                {
                    var keyPair = builder.GenerateAsymmetricKeyPair(Enumerable.Repeat((byte)0x00, 32).ToArray());
                    var token = builder
                        .WithKey(keyPair.SecretKey)
                        .Issuer(issuer)
                        .Encode();
                    return (token, keyPair.PublicKey);
                }
                default:
                    throw new InvalidEnumArgumentException();
            }
        }
    }
}