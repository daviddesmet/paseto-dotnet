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
    private const string IssuedBy = "Paragon Initiative Enterprises";
    private const string PublicKeyV1 = "<RSAKeyValue><Modulus>2Q3n8GRPEbcxAtT+uwsBnY08hhJF+Fby0MM1v5JbwlnQer7HmjKsaS97tbfnl87BwF15eKkxqHI12ntCSezxozhaUrgXCGVAXnUmZoioXTdtJgapFzBob88tLKhpWuoHdweRu9yGcWW3pD771zdFrRwa3h5alC1MAqAMHNid2D56TTsRj4CAfLSZpSsfmswfmHhDGqX7ZN6g/TND6kXjq4fPceFsb6yaKxy0JmtMomVqVTW3ggbVJhqJFOabwZ83/DjwqWEAJvfldz5g9LjvuislO5mJ9QEHBu7lnogKuX5g9PRTqP3c6Kus0/ldZ8CZvwWpxnxnwMRH10/UZ8TepQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
    private const string TokenV1 = "v1.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEzMDc1MzMifTzjEcgP2a3p_IrMPuU9bH8OvOmV5Olr8DFK3rFu_7SngF_pZ0cU1X9w590YQeZTy37B1bPouoXZDQ9JDYBfalxG0cNn2aP4iKHgYuyrOqHaUTmbNeooKOvDPwwl6CFO3spTTANLK04qgPJnixeb9mvjby2oM7Qpmn28HAwwr_lSoOMPhiUSCKN4u-SA6G6OddQTuXY-PCV1VtgQA83f0J6Yy3x7MGH9vvqonQSuOG6EGLHJ09p5wXllHQyGZcRm_654aKpwh8CXe3w8ol3OfozGCMFF_TLo_EeX0iKSkE8AQxkrQ-Fe-3lP_t7xPkeNhJPnhAa0-DGLSFQIILsL31M";
    private const string PublicKeyV2 = "rJRRV5JmY3BRUmyWu2CRa1EnUSSNbOgrAMTIsgbX3Z4=";
    private const string TokenV2 = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjIwMTgtMDQtMDdUMDU6MDQ6MDcuOTE5NjM3NVoifTuR3EYYCG12DjhIqPKiVmTkKx2ewCDrYNZHcoewiF-lpFeaFqKW3LkEgnW28UZxrBWA5wrLFCR5FP1qUlMeqQA";
    private const string LocalKeyV2 = "37ZJdkLlZ43aF8UO7GWqi7GrdO0zDZSpSFLNTAdmKdk=";
    private const string LocalTokenV2 = "v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248m9GasN_K5Yw2-CJksfXlbnEsTQHSMi49pqRzpvDTfo705J1ol98tc2e2Up62_4stDlPZQLAAwDeAQK0tS14h8JSYYunq3kvkeVTq6aNyCdw";
    private const string LocalTokenWithFooterV2 = "v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248m9GasN_K5Yw2-CJksfXlbnEsTQHSMi49pqRzpvDTfo705J1ol98tc2e2Up62_4stDlPZQLAAwDeAQK0tS14h8PyCfJzDW_mg6Bky_oW2HZw.eyJraWQiOiJnYW5kYWxmMCJ9";
    private const string ExpectedPublicPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T05:04:07.9196375Z\"}";
    private const string ExpectedLocalPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T04:57:18.5865183Z\"}";
    private const string ExpectedFooter = "{\"kid\":\"gandalf0\"}";

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
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(null, Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenGenerationEmptyKeyFails()
    {
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(new byte[0], Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationNullKeyFails()
    {
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(null, Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationEmptyKeyFails()
    {
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(new byte[0], Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenGenerationEmptyPayloadFails()
    {
        // Arrange
        var seed = new byte[32]; // signingKey
        RandomNumberGenerator.Create().GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

        // Act & Assert
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(sk, Encryption.AsymmetricSecretKey).Encode());
    }

    [Fact]
    public void Version2BuilderLocalTokenGenerationEmptyPayloadFails()
    {
        // Arrange
        var seed = new byte[32]; // signingKey
        RandomNumberGenerator.Create().GetBytes(seed);
        var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

        // Act & Assert
        Assert.Throws<PasetoBuilderException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(sk, Encryption.SymmetricKey).Encode());
    }

    [Fact]
    public void Version2BuilderPublicTokenDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
                                         .WithKey(Convert.FromBase64String(PublicKeyV2), Encryption.AsymmetricPublicKey)
                                         .Decode(TokenV2);

        // Assert
        payload.Should().NotBeNull();
        payload.Should().Be(ExpectedPublicPayload);
    }

    [Fact]
    public void Version2BuilderLocalTokenDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
                                         .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
                                         .Decode(LocalTokenV2);

        // Assert
        payload.Should().NotBeNull();
        payload.Should().Be(ExpectedLocalPayload);
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingTest()
    {
        // Arrange & Act
        var payload = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
                                         .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
                                         .Decode(LocalTokenWithFooterV2);

        // Assert
        payload.Should().NotBeNull();
        payload.Should().Be(ExpectedLocalPayload);
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingToObjectTest()
    {
        // Arrange & Act
        var data = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
                                      .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
                                      .DecodeToObject(LocalTokenWithFooterV2);

        // Assert
        data.Should().NotBeNull();
    }

    [Fact]
    public void Version2BuilderLocalTokenWithFooterDecodingFooterOnlyTest()
    {
        // Arrange & Act
        var footer = new PasetoBuilder().DecodeFooter(LocalTokenWithFooterV2);

        // Assert
        footer.Should().NotBeNull();
        footer.Should().Be(ExpectedFooter);
    }

    [Fact]
    public void Version2BuilderTokenDecodingNullKeyFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(null).Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingEmptyKeyFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder().UseV2(Purpose.Local).WithKey(new byte[0], Encryption.SymmetricKey).Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingNullTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(new byte[32], Encryption.AsymmetricPublicKey).Decode(null));

    [Fact]
    public void Version2BuilderTokenDecodingEmptyTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(new byte[32], Encryption.AsymmetricPublicKey).Decode(string.Empty));

    //[Fact]
    //public void Version2BuilderTokenDecodingInvalidTokenFails() => Assert.Throws<SignatureVerificationException>(() => new PasetoBuilder().UseV2(Purpose.Public).WithKey(Convert.FromBase64String(PublicKeyV2), Encryption.AsymmetricPublicKey).Decode("v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV2cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs"));

    #endregion
}
