namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using FluentAssertions;
using NaCl.Core.Internal;
using Xunit;

using Paseto.Builder;
using Paseto.Cryptography;
using static Paseto.Tests.TestHelper;

public class PasetoBuilderTests
{
    private const string LocalKey = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    private const string Footer = "arbitrary-string-that-isn't-json";

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

    public static IEnumerable<object[]> LocalDecodeData => new[]
    {
        new object[] { ProtocolVersion.V1, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9" },
        new object[] { ProtocolVersion.V2, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9" },
        new object[] { ProtocolVersion.V3, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9" },
        new object[] { ProtocolVersion.V4, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9" }
    };

    public static IEnumerable<object[]> PublicEncodeData => new[]
    {
        new object[] { ProtocolVersion.V1, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9\nGCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N\n02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJ\nAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNx\nkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPI\nidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3\nqfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0Jo\nWdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0Oy\nA0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9\nq33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+\n1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB\n42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04\nFfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUV\nrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znw\nAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZ\nxCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o\n/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2\nepTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R\n3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9h\nB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHk\nb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJ\nx/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT\n3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwm\npcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxI\nuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy\n-----END RSA PRIVATE KEY-----" },
        new object[] { ProtocolVersion.V2, "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2" },
        new object[] { ProtocolVersion.V3, "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96" },
        new object[] { ProtocolVersion.V4, "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2" }
    };

    [Theory(DisplayName = "Should succeed on GenerateSymmetricKey when dependencies are provided")]
    [InlineData(ProtocolVersion.V1, 32)]
    [InlineData(ProtocolVersion.V2, 32)]
    [InlineData(ProtocolVersion.V3, 32)]
    [InlineData(ProtocolVersion.V4, 32)]
    public void ShouldSucceedOnGenerateSymmetricKeyWhenDependenciesAreProvided(ProtocolVersion version, int keySize)
    {
        var pasetoKey = new PasetoBuilder().Use(version, Purpose.Local)
                                           .GenerateSymmetricKey();

        pasetoKey.Should().NotBeNull();
        pasetoKey.Key.IsEmpty.Should().BeFalse();
        pasetoKey.Key.Length.Should().Be(keySize);
    }

    [Fact(DisplayName = "Should throw exception on GenerateSymmetricKey when no dependencies are provided")]
    public void ShouldThrowExceptionOnGenerateSymmetricKeyWhenNoDependenciesAreProvided()
    {
        Action act = () => new PasetoBuilder().GenerateSymmetricKey();

        act.Should().Throw<PasetoBuilderException>().WithMessage("Can't generate serialized key. Check if you have call the 'Use' method.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateSymmetricKey when incorrect purpose is provided")]
    [InlineData(ProtocolVersion.V1)]
    [InlineData(ProtocolVersion.V2)]
    [InlineData(ProtocolVersion.V3)]
    [InlineData(ProtocolVersion.V4)]
    public void ShouldThrowExceptionOnGenerateSymmetricKeyWhenIncorrectPurposeIsProvided(ProtocolVersion version)
    {
        var incorrectPurpose = Purpose.Public;

        Action act = () => new PasetoBuilder().Use(version, incorrectPurpose)
                                              .GenerateSymmetricKey();

        act.Should().Throw<PasetoBuilderException>().WithMessage($"Can't generate symmetric key. {incorrectPurpose} purpose is not compatible.");
    }

    [Theory(DisplayName = "Should succeed on GenerateAsymmetricKeyPair when Seed is provided")]
    [InlineData(ProtocolVersion.V1, 0, 0)]
    [InlineData(ProtocolVersion.V2, 64, 32)]
    [InlineData(ProtocolVersion.V3, 48, 49)]
    [InlineData(ProtocolVersion.V4, 64, 32)]
    public void ShouldSucceedOnGenerateAsymmetricKeyPairWhenSeedIsProvided(ProtocolVersion version, int secretKeyLength, int publicKeyLength)
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);

        var pasetoKey = new PasetoBuilder().Use(version, Purpose.Public)
                                           .GenerateAsymmetricKeyPair(seed);

        pasetoKey.Should().NotBeNull();
        pasetoKey.SecretKey.Key.IsEmpty.Should().BeFalse();
        pasetoKey.PublicKey.Key.IsEmpty.Should().BeFalse();

        if (version == ProtocolVersion.V1) return;
        pasetoKey.SecretKey.Key.Length.Should().Be(secretKeyLength);
        pasetoKey.PublicKey.Key.Length.Should().Be(publicKeyLength);
    }

    [Fact(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when no dependencies are provided")]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenNoDependenciesAreProvided()
    {
        Action act = () => new PasetoBuilder().GenerateAsymmetricKeyPair();

        act.Should().Throw<PasetoBuilderException>().WithMessage("Can't generate serialized key. Check if you have call the 'Use' method.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when incorrect purpose is provided")]
    [InlineData(ProtocolVersion.V1)]
    [InlineData(ProtocolVersion.V2)]
    [InlineData(ProtocolVersion.V3)]
    [InlineData(ProtocolVersion.V4)]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenIncorrectPurposeIsProvided(ProtocolVersion version)
    {
        var incorrectPurpose = Purpose.Local;

        Action act = () => new PasetoBuilder().Use(version, incorrectPurpose)
                                              .GenerateAsymmetricKeyPair();

        act.Should().Throw<PasetoBuilderException>().WithMessage($"Can't generate symmetric key. {incorrectPurpose} purpose is not compatible.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when invalid seed is provided")]
    [InlineData(ProtocolVersion.V2, null)]
    [InlineData(ProtocolVersion.V2, new byte[0])]
    [InlineData(ProtocolVersion.V2, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V2, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V3, null)]
    [InlineData(ProtocolVersion.V3, new byte[0])]
    [InlineData(ProtocolVersion.V3, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V3, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V4, null)]
    [InlineData(ProtocolVersion.V4, new byte[0])]
    [InlineData(ProtocolVersion.V4, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V4, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenInvalidSeedIsProvided(ProtocolVersion version, byte[] seed)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Public)
                                              .GenerateAsymmetricKeyPair(seed);

        if (seed is null)
            act.Should().Throw<ArgumentNullException>();
        else
            act.Should().Throw<ArgumentException>().WithMessage("The seed length in bytes must be*");
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key and optional Footer when dependencies are provided")]
    [InlineData(ProtocolVersion.V1)]
    [InlineData(ProtocolVersion.V2)]
    [InlineData(ProtocolVersion.V3)]
    [InlineData(ProtocolVersion.V4)]
    public void ShouldSucceedOnLocalEncodeWithByteArrayKeyAndOptionalFooterWhenDependenciesAreProvided(ProtocolVersion version)
    {
        var token = new PasetoBuilder().Use(version, Purpose.Local)
                                                   .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
                                                   .AddClaim("data", "this is a secret message")
                                                   .Issuer("https://github.com/daviddesmet/paseto-dotnet")
                                                   .Subject(Guid.NewGuid().ToString())
                                                   .Audience("https://paseto.io")
                                                   .NotBefore(DateTime.UtcNow.AddMinutes(5))
                                                   .IssuedAt(DateTime.UtcNow)
                                                   .Expiration(DateTime.UtcNow.AddHours(1))
                                                   .TokenIdentifier("123456ABCD")
                                                   .AddFooter(Footer)
                                                   .Encode();

        token.Should().NotBeNullOrEmpty();
        token.Should().StartWith($"v{(int)version}.local.");
        token.Split('.').Should().HaveCount(4);
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key and optional Footer Payload when dependencies are provided")]
    [InlineData(ProtocolVersion.V1)]
    [InlineData(ProtocolVersion.V2)]
    [InlineData(ProtocolVersion.V3)]
    [InlineData(ProtocolVersion.V4)]
    public void ShouldSucceedOnLocalEncodeWithByteArrayKeyAndOptionalFooterPayloadWhenDependenciesAreProvided(ProtocolVersion version)
    {
        var token = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
            .AddClaim("data", "this is a secret message")
            .Issuer("https://github.com/daviddesmet/paseto-dotnet")
            .Subject(Guid.NewGuid().ToString())
            .Audience("https://paseto.io")
            .NotBefore(DateTime.UtcNow.AddMinutes(5))
            .IssuedAt(DateTime.UtcNow)
            .Expiration(DateTime.UtcNow.AddHours(1))
            .TokenIdentifier("123456ABCD")
            .AddFooter(new PasetoPayload { { "kid", "gandalf0" } })
            .Encode();

        token.Should().NotBeNullOrEmpty();
        token.Should().StartWith($"v{(int)version}.local.");
        token.Split('.').Should().HaveCount(4);
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key when dependencies are provided")]
    [InlineData(ProtocolVersion.V1)]
    [InlineData(ProtocolVersion.V2)]
    [InlineData(ProtocolVersion.V3)]
    [InlineData(ProtocolVersion.V4)]
    public void ShouldSucceedOnLocalEncodeWithByteArrayKeyWhenDependenciesAreProvided(ProtocolVersion version)
    {
        var token = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
            .AddClaim("data", "this is a secret message")
            .Issuer("https://github.com/daviddesmet/paseto-dotnet")
            .Subject(Guid.NewGuid().ToString())
            .Audience("https://paseto.io")
            .NotBefore(DateTime.UtcNow.AddMinutes(5))
            .IssuedAt(DateTime.UtcNow)
            .Expiration(DateTime.UtcNow.AddHours(1))
            .TokenIdentifier("123456ABCD")
            .Encode();

        token.Should().NotBeNullOrEmpty();
        token.Should().StartWith($"v{(int)version}.local.");
        token.Split('.').Should().HaveCount(3);
    }

    [Theory(DisplayName = "Should succeed on Public Encode with Byte Array Key and optional Footer Payload when dependencies are provided")]
    [MemberData(nameof(PublicEncodeData))]
    public void ShouldSucceedOnPublicEncodeWithByteArrayKeyAndOptionalFooterPayloadWhenDependenciesAreProvided(ProtocolVersion version, string secretKey)
    {
        var token = new PasetoBuilder().Use(version, Purpose.Public)
            .WithKey(ReadKey(secretKey), Encryption.AsymmetricSecretKey)
            .AddClaim("data", "this is a secret message")
            .Issuer("https://github.com/daviddesmet/paseto-dotnet")
            .Subject(Guid.NewGuid().ToString())
            .Audience("https://paseto.io")
            .NotBefore(DateTime.UtcNow.AddMinutes(5))
            .IssuedAt(DateTime.UtcNow)
            .Expiration(DateTime.UtcNow.AddHours(1))
            .TokenIdentifier("123456ABCD")
            .AddFooter(new PasetoPayload { { "kid", "gandalf0" } })
            .Encode();

        token.Should().NotBeNullOrEmpty();
        token.Should().StartWith($"v{(int)version}.public.");
        token.Split('.').Should().HaveCount(4);
    }

    [Theory(DisplayName = "Should succeed on Public Encode with Byte Array Key when dependencies are provided")]
    [MemberData(nameof(PublicEncodeData))]
    public void ShouldSucceedOnPublicEncodeWithByteArrayKeyWhenDependenciesAreProvided(ProtocolVersion version, string secretKey)
    {
        var token = new PasetoBuilder().Use(version, Purpose.Public)
            .WithKey(ReadKey(secretKey), Encryption.AsymmetricSecretKey)
            .AddClaim("data", "this is a secret message")
            .Issuer("https://github.com/daviddesmet/paseto-dotnet")
            .Subject(Guid.NewGuid().ToString())
            .Audience("https://paseto.io")
            .NotBefore(DateTime.UtcNow.AddMinutes(5))
            .IssuedAt(DateTime.UtcNow)
            .Expiration(DateTime.UtcNow.AddHours(1))
            .TokenIdentifier("123456ABCD")
            .Encode();

        token.Should().NotBeNullOrEmpty();
        token.Should().StartWith($"v{(int)version}.public.");
        token.Split('.').Should().HaveCount(3);
    }

    [Fact(DisplayName = "Should throw exception on Encode when Use is not called")]
    public void ShouldThrowExceptionOnEncodeWhenUseIsNotCalled()
    {
        Action act = () => new PasetoBuilder().Encode();

        act.Should().Throw<PasetoBuilderException>().WithMessage("Can't build a token. Check if you have call the 'Use' method.");
    }

    [Theory(DisplayName = "Should throw exception on Encode when Use is passing an invalid or unsupported protocol version")]
    [InlineData("v0", Purpose.Local)]
    [InlineData("v0", Purpose.Public)]
    [InlineData("vv", Purpose.Local)]
    [InlineData("vv", Purpose.Public)]
    [InlineData("x1", Purpose.Local)]
    [InlineData("x1", Purpose.Public)]
    [InlineData("p1", Purpose.Local)]
    [InlineData("p1", Purpose.Public)]
    public void ShouldThrowExceptionOnEncodeWhenUseIsPassingInvalidProtocol(string version, Purpose purpose)
    {
        Action act = () => new PasetoBuilder().Use(version, purpose)
                                              .Encode();

        act.Should().Throw<PasetoNotSupportedException>().WithMessage("The protocol version * is currently not supported.");
    }

    [Theory(DisplayName = "Should throw exception on Encode when WithKey is not called")]
    [InlineData(ProtocolVersion.V1, Purpose.Local)]
    [InlineData(ProtocolVersion.V1, Purpose.Public)]
    [InlineData(ProtocolVersion.V2, Purpose.Local)]
    [InlineData(ProtocolVersion.V2, Purpose.Public)]
    [InlineData(ProtocolVersion.V3, Purpose.Local)]
    [InlineData(ProtocolVersion.V3, Purpose.Public)]
    [InlineData(ProtocolVersion.V4, Purpose.Local)]
    [InlineData(ProtocolVersion.V4, Purpose.Public)]
    public void ShouldThrowExceptionOnEncodeWhenWithKeyIsNotCalled(ProtocolVersion version, Purpose purpose)
    {
        Action act = () => new PasetoBuilder().Use(version, purpose)
                                              .Encode();

        act.Should().Throw<PasetoBuilderException>().WithMessage("Can't build a token. Check if you have call the 'WithKey' method.");
    }

    [Theory(DisplayName = "Should throw exception on Encode when Payload is not added")]
    [InlineData(ProtocolVersion.V1, Purpose.Local)]
    [InlineData(ProtocolVersion.V1, Purpose.Public)]
    [InlineData(ProtocolVersion.V2, Purpose.Local)]
    [InlineData(ProtocolVersion.V2, Purpose.Public)]
    [InlineData(ProtocolVersion.V3, Purpose.Local)]
    [InlineData(ProtocolVersion.V3, Purpose.Public)]
    [InlineData(ProtocolVersion.V4, Purpose.Local)]
    [InlineData(ProtocolVersion.V4, Purpose.Public)]
    public void ShouldThrowExceptionOnEncodeWhenPayloadIsNotAdded(ProtocolVersion version, Purpose purpose)
    {
        Action act = () => new PasetoBuilder().Use(version, purpose)
                                              .WithKey(Array.Empty<byte>(), purpose == Purpose.Local ? Encryption.SymmetricKey : Encryption.AsymmetricSecretKey)
                                              .Encode();

        act.Should().Throw<PasetoBuilderException>().WithMessage("Can't build a token. Check if you have call the 'AddClaim' method.");
    }

    [Theory(DisplayName = "Should throw exception on Local Encode when invalid key is provided")]
    [InlineData(ProtocolVersion.V1, null)]
    [InlineData(ProtocolVersion.V1, new byte[0])]
    [InlineData(ProtocolVersion.V1, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V2, null)]
    [InlineData(ProtocolVersion.V2, new byte[0])]
    [InlineData(ProtocolVersion.V2, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V3, null)]
    [InlineData(ProtocolVersion.V3, new byte[0])]
    [InlineData(ProtocolVersion.V3, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V4, null)]
    [InlineData(ProtocolVersion.V4, new byte[0])]
    [InlineData(ProtocolVersion.V4, new byte[] { 0x00, 0x00 })]
    public void ShouldThrowExceptionOnLocalEncodeWhenInvalidKeyIsProvided(ProtocolVersion version, byte[] key)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Local)
                                              .WithKey(key, Encryption.SymmetricKey)
                                              .AddClaim("data", "this is a secret message")
                                              .Expiration(DateTime.UtcNow.AddHours(1))
                                              .Encode();

        act.Should().Throw<ArgumentException>().WithMessage("The key length in bytes must be*");
    }

    [Theory(DisplayName = "Should throw exception on Public Encode when invalid key is provided")]
    [InlineData(ProtocolVersion.V1, null)]
    [InlineData(ProtocolVersion.V1, new byte[0])]
    [InlineData(ProtocolVersion.V1, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V2, null)]
    [InlineData(ProtocolVersion.V2, new byte[0])]
    [InlineData(ProtocolVersion.V2, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V3, null)]
    [InlineData(ProtocolVersion.V3, new byte[0])]
    [InlineData(ProtocolVersion.V3, new byte[] { 0x00, 0x00 })]
    [InlineData(ProtocolVersion.V4, null)]
    [InlineData(ProtocolVersion.V4, new byte[0])]
    [InlineData(ProtocolVersion.V4, new byte[] { 0x00, 0x00 })]
    public void ShouldThrowExceptionOnPublicEncodeWhenInvalidKeyIsProvided(ProtocolVersion version, byte[] key)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Public)
                                              .WithKey(key, Encryption.AsymmetricSecretKey)
                                              .AddClaim("data", "this is a secret message")
                                              .Expiration(DateTime.UtcNow.AddHours(1))
                                              .Encode();

        act.Should().Throw<ArgumentException>();
    }

    [Theory(DisplayName = "Should succeed on Local Decode with Byte Array Key when dependencies are provided")]
    [MemberData(nameof(LocalDecodeData))]
    public void ShouldSucceedOnLocalDecodeWithByteArrayKeyWhenDependenciesAreProvided(ProtocolVersion version, string sharedKey, string token)
    {
        var result = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(sharedKey), Encryption.SymmetricKey)
            .Decode(token);

        result.IsValid.Should().BeTrue();
        result.Paseto.Should().NotBeNull();
        result.Exception.Should().BeNull();
    }

    // TODO: Decode tests (local and public)
    // TODO: Decode fails tests, include invalid header v1.remote.
    // TODO: Decode with payload validation (success and fails)
    // TODO: Decode only header and footer
    // TODO: Handle specific scenarios like out-of-order parameters WithKey before Use, etc...




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

    // [Fact]
    // public void Version2BuilderPublicTokenDecodingTest()
    // {
    //     // Arrange & Act
    //     var payload = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
    //                                      .WithKey(Convert.FromBase64String(PublicKeyV2), Encryption.AsymmetricPublicKey)
    //                                      .Decode(TokenV2);
    //
    //     // Assert
    //     payload.Should().NotBeNull();
    //     payload.Should().Be(ExpectedPublicPayload);
    // }

    // [Fact]
    // public void Version2BuilderLocalTokenDecodingTest()
    // {
    //     // Arrange & Act
    //     var result = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
    //                                      .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
    //                                      .Decode(LocalTokenV2);
    //
    //     // Assert
    //     result.Should().NotBeNull();
    //     result.Paseto.Should().NotBeNull();
    //     result.Paseto.RawPayload.Should().Be(ExpectedLocalPayload);
    // }

    // [Fact]
    // public void Version2BuilderLocalTokenWithFooterDecodingTest()
    // {
    //     // Arrange & Act
    //     var result = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
    //                                      .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
    //                                      .Decode(LocalTokenWithFooterV2);
    //
    //     // Assert
    //     result.Should().NotBeNull();
    //     result.Paseto.Should().NotBeNull();
    //     result.Paseto.RawPayload.Should().Be(ExpectedLocalPayload);
    // }

    // [Fact]
    // public void Version2BuilderLocalTokenWithFooterDecodingToObjectTest()
    // {
    //     // Arrange & Act
    //     var result = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Local)
    //                                   .WithKey(Convert.FromBase64String(LocalKeyV2), Encryption.SymmetricKey)
    //                                   .Decode(LocalTokenWithFooterV2);
    //
    //     // Assert
    //     result.IsValid.Should().BeTrue();
    //     result.Paseto.Should().NotBeNull();
    // }

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
