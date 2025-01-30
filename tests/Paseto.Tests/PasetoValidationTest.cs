namespace Paseto.Tests;

using System.ComponentModel;
using System.Linq;

using Shouldly;
using Builder;
using Cryptography.Key;
using Xunit;

public sealed class PasetoValidationTest
{
    [Theory(DisplayName = "Should succeed on token with valid audience")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithValidAudienceValidationSucceeds(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateAudience = true,
            ValidAudience = "valid-audience",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Audience, "valid-audience");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(true);
    }

    [Theory(DisplayName = "Should fail on token with invalid audience")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithInValidAudienceValidationFails(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateAudience = true,
            ValidAudience = "valid-audience",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Audience, "invalid-audience");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(false);
    }

    [Theory(DisplayName = "Should succeed on token with valid issuer")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithValidIssuerValidationSucceeds(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidIssuer = "valid-issuer",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Issuer, "valid-issuer");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(true);
    }

    [Theory(DisplayName = "Should fail on token with invalid issuer")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithInValidIssuerValidationFails(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidIssuer = "valid-issuer",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Issuer, "invalid-issuer");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(false);
    }

    [Theory(DisplayName = "Should succeed on token with valid subject")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithValidSubjectValidationSucceeds(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateSubject = true,
            ValidSubject = "valid-subject",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Subject, "valid-subject");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(true);
    }

    [Theory(DisplayName = "Should fail on token with invalid subject")]
    [MemberData(nameof(TestHelper.AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void TokenWithInValidSubjectValidationFails(ProtocolVersion version, Purpose purpose)
    {
        var validationParameters = new PasetoTokenValidationParameters()
        {
            ValidateSubject = true,
            ValidSubject = "valid-subject",
        };

        var (token, decodeKey) = GenerateToken(version, purpose, PasetoRegisteredClaimNames.Subject, "invalid-subject");
        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithKey(decodeKey)
            .Decode(token, validationParameters);

        decoded.IsValid.ShouldBe(false);
    }

    private static (string token, PasetoKey decodeKey) GenerateToken(ProtocolVersion version, Purpose purpose, string claimName, string claimValue)
    {
        var builder = new PasetoBuilder()
            .Use(version, purpose)
            .AddClaim(claimName, claimValue);

        switch (purpose)
        {
            case Purpose.Local:
            {
                var key = builder.GenerateSymmetricKey();
                var token = builder
                    .WithKey(key)
                    .Encode();
                return (token, key);
            }
            case Purpose.Public:
            {
                var keyPair = builder.GenerateAsymmetricKeyPair(Enumerable.Repeat((byte)0x00, 32).ToArray());
                var token = builder
                    .WithKey(keyPair.SecretKey)
                    .Encode();
                return (token, keyPair.PublicKey);
            }
            default:
                throw new InvalidEnumArgumentException();
        }
    }
}