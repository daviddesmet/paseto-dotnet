namespace Paseto.Tests;

using System;
using System.Security.Cryptography;

using FluentAssertions;
using Xunit;

using Paseto.Builder;
using Paseto.Cryptography;

public class PasetoBuilderTests
{
    private const string HelloPaseto = "Hello Paseto!";
    private const string PublicKeyV2 = "rJRRV5JmY3BRUmyWu2CRa1EnUSSNbOgrAMTIsgbX3Z4=";
    private const string TokenV2 = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjIwMTgtMDQtMDdUMDU6MDQ6MDcuOTE5NjM3NVoifTuR3EYYCG12DjhIqPKiVmTkKx2ewCDrYNZHcoewiF-lpFeaFqKW3LkEgnW28UZxrBWA5wrLFCR5FP1qUlMeqQA";

    #region Version 2

    [Fact]
    public void Version2BuilderPublicTokenGenerationTest()
    {
        // Arrange
        var seed = new byte[32]; // signingKey
        RandomNumberGenerator.Create().GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

        //var secret = Convert.ToBase64String(sk); //BitConverter.ToString(sk).Replace("-", string.Empty); // Hex Encoded

        // Act
        var token = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
                                       .WithKey(sk, Encryption.AsymmetricSecretKey)
                                       .AddClaim("example", HelloPaseto)
                                       .Expiration(DateTime.UtcNow.AddHours(24))
                                       .Encode();

        // Assert
        token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationTest()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Create().GetBytes(key);

        //key = Convert.FromBase64String(LocalKeyV2);

        // Act
        var token = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
                                       .WithKey(key, Encryption.SymmetricKey)
                                       .AddClaim("example", HelloPaseto)
                                       .Expiration(DateTime.UtcNow.AddHours(24))
                                       //.Expiration(DateTime.Parse("2018-04-07T04:57:18.5865183Z").ToUniversalTime())
                                       .Encode();

        // Assert
        token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterGenerationTest()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Create().GetBytes(key);

        //key = Convert.FromBase64String(LocalKeyV2);

        // Act
        var token = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
                                       .WithKey(key, Encryption.SymmetricKey)
                                       .AddClaim("example", HelloPaseto)
                                       .Expiration(DateTime.UtcNow.AddHours(24))
                                       //.Expiration(DateTime.Parse("2018-04-07T04:57:18.5865183Z").ToUniversalTime())
                                       .AddFooter(new PasetoPayload { { "kid", "gandalf0" } })
                                       .Encode();

        // Assert
        token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Version2BuilderPublicTokenGenerationNullKeyFails()
    {
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(null, Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenGenerationEmptyKeyFails()
    {
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(new byte[0], Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationNullKeyFails()
    {
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(null, Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationEmptyKeyFails()
    {
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(new byte[0], Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenGenerationEmptyPayloadFails()
    {
        // Arrange
        var seed = new byte[32]; // signingKey
        RandomNumberGenerator.Create().GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(sk, Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationEmptyPayloadFails()
    {
        // Arrange
        var seed = new byte[32]; // signingKey
        RandomNumberGenerator.Create().GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(sk, Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
                                         .WithKey(Convert.FromBase64String(PublicKeyV2), Encryption.AsymmetricSecretKey)
                                         .Decode(TokenV2);

        // Assert
        Assert.IsNotNull(payload);
        Assert.That(payload, Is.EqualTo(ExpectedPublicPayload));
    }

    [Fact]
    public void Version2BuilderLocalTokenDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder<Version2>()
                          .WithKey(Convert.FromBase64String(LocalKeyV2))
                          .AsLocal()
                          .Decode(LocalTokenV2);

        // Assert
        Assert.IsNotNull(payload);
        Assert.That(payload, Is.EqualTo(ExpectedLocalPayload));
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder<Version2>()
                          .WithKey(Convert.FromBase64String(LocalKeyV2))
                          .AsLocal()
                          .Decode(LocalTokenWithFooterV2);

        // Assert
        Assert.IsNotNull(payload);
        Assert.That(payload, Is.EqualTo(ExpectedLocalPayload));
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingToObjectTest()
    {
        // Arrange & Act
        var data = new PasetoBuilder<Version2>()
                       .WithKey(Convert.FromBase64String(LocalKeyV2))
                       .AsLocal()
                       .DecodeToObject(LocalTokenWithFooterV2);

        // Assert
        Assert.IsNotNull(data);
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingFooterOnlyTest()
    {
        // Arrange & Act
        var footer = new PasetoBuilder<Version2>().DecodeFooter(LocalTokenWithFooterV2);

        // Assert
        Assert.IsNotNull(footer);
        Assert.That(footer, Is.EqualTo(ExpectedFooter));
    }

    [Fact]
    public void Version2BuilderTokenDecodingNullKeyFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(null).Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingEmptyKeyFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(new byte[0]).Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingNullTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder<Version2>().WithKey(new byte[32]).AsPublic().Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingEmptyTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder<Version2>().WithKey(new byte[32]).AsPublic().Decode(string.Empty));

    [Fact]
    public void Version2BuilderTokenDecodingInvalidTokenFails() => Assert.Throws<SignatureVerificationException>(() => new PasetoBuilder<Version2>().WithKey(Convert.FromBase64String(PublicKeyV2)).AsPublic().Decode("v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV2cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs"));

    #endregion
}
