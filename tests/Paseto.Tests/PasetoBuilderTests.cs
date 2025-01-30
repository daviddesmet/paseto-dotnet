namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

using Shouldly;
using NaCl.Core.Internal;
using Xunit;

using Paseto.Builder;
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
        new object[] { ProtocolVersion.V1, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}" },
        new object[] { ProtocolVersion.V2, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}" },
        new object[] { ProtocolVersion.V3, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}" },
        new object[] { ProtocolVersion.V4, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}" }
    };

    public static IEnumerable<object[]> PublicEncodeData => new[]
    {
        new object[] { ProtocolVersion.V1, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9\nGCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N\n02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJ\nAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNx\nkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPI\nidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3\nqfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0Jo\nWdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0Oy\nA0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9\nq33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+\n1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB\n42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04\nFfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUV\nrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znw\nAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZ\nxCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o\n/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2\nepTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R\n3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9h\nB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHk\nb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJ\nx/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT\n3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwm\npcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxI\nuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy\n-----END RSA PRIVATE KEY-----" },
        new object[] { ProtocolVersion.V2, "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2" },
        new object[] { ProtocolVersion.V3, "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96" },
        new object[] { ProtocolVersion.V4, "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2" }
    };

    public static IEnumerable<object[]> PublicDecodeData => new[]
    {
        new object[]
        {
            ProtocolVersion.V1,
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p5GHgwoGW\nwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwx\nKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1\nOt0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAA\npVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6al\nUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8\nowIDAQAB\n-----END PUBLIC KEY-----",
            "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
            "discarded-anyway"
        },
        new object[]
        {
            ProtocolVersion.V2,
            "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
            "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
            "discarded-anyway"
        },
        new object[]
        {
            ProtocolVersion.V3,
            "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
            "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
            "{\"test-vector\":\"3-S-3\"}"
        },
        new object[]
        {
            ProtocolVersion.V4,
            "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
            "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
            "{\"test-vector\":\"4-S-3\"}"
        }
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

        pasetoKey.ShouldNotBeNull();
        pasetoKey.Key.IsEmpty.ShouldBe(false);
        pasetoKey.Key.Length.ShouldBe(keySize);
    }

    [Fact(DisplayName = "Should throw exception on GenerateSymmetricKey when no dependencies are provided")]
    public void ShouldThrowExceptionOnGenerateSymmetricKeyWhenNoDependenciesAreProvided()
    {
        Action act = () => new PasetoBuilder().GenerateSymmetricKey();

        act.ShouldThrow<PasetoBuilderException>("Can't generate serialized key. Check if you have call the 'Use' method.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateSymmetricKey when incorrect purpose is provided")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldThrowExceptionOnGenerateSymmetricKeyWhenIncorrectPurposeIsProvided(ProtocolVersion version)
    {
        var incorrectPurpose = Purpose.Public;

        Action act = () => new PasetoBuilder().Use(version, incorrectPurpose)
                                              .GenerateSymmetricKey();

        act.ShouldThrow<PasetoBuilderException>($"Can't generate symmetric key. {incorrectPurpose} purpose is not compatible.");
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

        pasetoKey.ShouldNotBeNull();
        pasetoKey.SecretKey.Key.IsEmpty.ShouldBe(false);
        pasetoKey.PublicKey.Key.IsEmpty.ShouldBe(false);

        if (version == ProtocolVersion.V1) return;
        pasetoKey.SecretKey.Key.Length.ShouldBe(secretKeyLength);
        pasetoKey.PublicKey.Key.Length.ShouldBe(publicKeyLength);
    }

    [Fact(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when no dependencies are provided")]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenNoDependenciesAreProvided()
    {
        Action act = () => new PasetoBuilder().GenerateAsymmetricKeyPair();

        act.ShouldThrow<PasetoBuilderException>("Can't generate serialized key. Check if you have call the 'Use' method.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when incorrect purpose is provided")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenIncorrectPurposeIsProvided(ProtocolVersion version)
    {
        var incorrectPurpose = Purpose.Local;

        Action act = () => new PasetoBuilder().Use(version, incorrectPurpose)
                                              .GenerateAsymmetricKeyPair();

        act.ShouldThrow<PasetoBuilderException>($"Can't generate symmetric key. {incorrectPurpose} purpose is not compatible.");
    }

    [Theory(DisplayName = "Should throw exception on GenerateAsymmetricKeyPair when invalid seed is provided")]
    [MemberData(nameof(VersionsAndInvalidSeedData))]
    public void ShouldThrowExceptionOnGenerateAsymmetricKeyPairWhenInvalidSeedIsProvided(ProtocolVersion version, byte[] seed)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Public)
                                              .GenerateAsymmetricKeyPair(seed);

        if (seed is null)
            act.ShouldThrow<ArgumentNullException>();
        else
            act.ShouldThrow<ArgumentException>("The seed length in bytes must be*");
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key and optional Footer when dependencies are provided")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
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

        token.ShouldNotBeNullOrEmpty();
        token.ShouldStartWith($"v{(int)version}.local.");
        token.Split('.').Length.ShouldBe(4);
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key and optional Footer Payload when dependencies are provided")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
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

        token.ShouldNotBeNullOrEmpty();
        token.ShouldStartWith($"v{(int)version}.local.");
        token.Split('.').Length.ShouldBe(4);
    }

    [Theory(DisplayName = "Should succeed on Local Encode with Byte Array Key when dependencies are provided")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
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

        token.ShouldNotBeNullOrEmpty();
        token.ShouldStartWith($"v{(int)version}.local.");
        token.Split('.').Length.ShouldBe(3);
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

        token.ShouldNotBeNullOrEmpty();
        token.ShouldStartWith($"v{(int)version}.public.");
        token.Split('.').Length.ShouldBe(4);
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

        token.ShouldNotBeNullOrEmpty();
        token.ShouldStartWith($"v{(int)version}.public.");
        token.Split('.').Length.ShouldBe(3);
    }

    [Fact(DisplayName = "Should throw exception on Encode when Use is not called")]
    public void ShouldThrowExceptionOnEncodeWhenUseIsNotCalled()
    {
        Action act = () => new PasetoBuilder().Encode();

        act.ShouldThrow<PasetoBuilderException>("Can't build a token. Check if you have call the 'Use' method.");
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

        act.ShouldThrow<PasetoNotSupportedException>("The protocol version * is currently not supported.");
    }

    [Theory(DisplayName = "Should throw exception on Encode when WithKey is not called")]
    [MemberData(nameof(AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void ShouldThrowExceptionOnEncodeWhenWithKeyIsNotCalled(ProtocolVersion version, Purpose purpose)
    {
        Action act = () => new PasetoBuilder().Use(version, purpose)
                                              .Encode();

        act.ShouldThrow<PasetoBuilderException>("Can't build a token. Check if you have call the 'WithKey' method.");
    }

    [Theory(DisplayName = "Should throw exception on Encode when Payload is not added")]
    [MemberData(nameof(AllVersionsAndPurposesData), MemberType = typeof(TestHelper))]
    public void ShouldThrowExceptionOnEncodeWhenPayloadIsNotAdded(ProtocolVersion version, Purpose purpose)
    {
        Action act = () => new PasetoBuilder().Use(version, purpose)
                                              .WithKey(Array.Empty<byte>(), purpose == Purpose.Local ? Encryption.SymmetricKey : Encryption.AsymmetricSecretKey)
                                              .Encode();

        act.ShouldThrow<PasetoBuilderException>("Can't build a token. Check if you have call the 'AddClaim' method.");
    }

    [Theory(DisplayName = "Should throw exception on Local Encode when invalid key is provided")]
    [MemberData(nameof(VersionsAndInvalidKeyData))]
    public void ShouldThrowExceptionOnLocalEncodeWhenInvalidKeyIsProvided(ProtocolVersion version, byte[] key)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Local)
                                              .WithKey(key, Encryption.SymmetricKey)
                                              .AddClaim("data", "this is a secret message")
                                              .Expiration(DateTime.UtcNow.AddHours(1))
                                              .Encode();

        act.ShouldThrow<ArgumentException>("The key length in bytes must be*");
    }

    [Theory(DisplayName = "Should throw exception on Public Encode when invalid key is provided")]
    [MemberData(nameof(VersionsAndInvalidKeyData))]
    public void ShouldThrowExceptionOnPublicEncodeWhenInvalidKeyIsProvided(ProtocolVersion version, byte[] key)
    {
        Action act = () => new PasetoBuilder().Use(version, Purpose.Public)
                                              .WithKey(key, Encryption.AsymmetricSecretKey)
                                              .AddClaim("data", "this is a secret message")
                                              .Expiration(DateTime.UtcNow.AddHours(1))
                                              .Encode();

        act.ShouldThrow<ArgumentException>();
    }

    [Theory(DisplayName = "Should succeed on Local Decode with Byte Array Key and optional Footer when dependencies are provided")]
    [MemberData(nameof(LocalDecodeData))]
    public void ShouldSucceedOnLocalDecodeWithByteArrayKeyAndOptionalFooterWhenDependenciesAreProvided(ProtocolVersion version, string sharedKey, string token, string footer)
    {
        var result = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(sharedKey), Encryption.SymmetricKey)
            .AddFooter(footer)
            .Decode(token);

        result.IsValid.ShouldBe(true);
        result.Paseto.ShouldNotBeNull();
        result.Paseto.Payload["data"].ShouldNotBeNull();
        result.Paseto.Payload["exp"].ShouldNotBeNull();
        result.Exception.ShouldBeNull();
    }

    [Theory(DisplayName = "Should succeed on Public Decode with Byte Array Key and optional Footer and optional implicit assertion when dependencies are provided")]
    [MemberData(nameof(PublicDecodeData))]
    public void ShouldSucceedOnPublicDecodeWithByteArrayKeyAndOptionalFooterAndOptionalImplicitAssertionWhenDependenciesAreProvided(ProtocolVersion version, string sharedKey, string token, string footer, string assertion)
    {
        var result = new PasetoBuilder().Use(version, Purpose.Public)
            .WithKey(ReadKey(sharedKey), Encryption.AsymmetricPublicKey)
            .AddFooter(footer)
            .AddImplicitAssertion(assertion)
            .Decode(token);

        result.IsValid.ShouldBe(true);
        result.Paseto.ShouldNotBeNull();
        result.Paseto.Payload["data"].ShouldNotBeNull();
        result.Paseto.Payload["exp"].ShouldNotBeNull();
        result.Exception.ShouldBeNull();
    }

    [Theory(DisplayName = "Should fail on Local Decode when Token is not valid")]
    [InlineData(ProtocolVersion.V1, "x1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg")]
    [InlineData(ProtocolVersion.V1, "v1.remote.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg")]
    [InlineData(ProtocolVersion.V2, "x2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA")]
    [InlineData(ProtocolVersion.V2, "v2.remote.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA")]
    [InlineData(ProtocolVersion.V3, "x3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM")]
    [InlineData(ProtocolVersion.V3, "v3.remote.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM")]
    [InlineData(ProtocolVersion.V4, "x4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9")]
    [InlineData(ProtocolVersion.V4, "v4.remote.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9")]
    public void ShouldFailOnLocalDecodeWhenTokenIsInvalid(ProtocolVersion version, string token)
    {
        var result = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
            .Decode(token);

        result.IsValid.ShouldBe(false);
        result.Exception.ShouldNotBeNull();
    }

    [Theory(DisplayName = "Should fail on Local Decode when Token's Footer is not valid")]
    [InlineData(ProtocolVersion.V1, "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp6byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}")]
    [InlineData(ProtocolVersion.V2, "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc6MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")]
    [InlineData(ProtocolVersion.V3, "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp6byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}")]
    [InlineData(ProtocolVersion.V4, "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc6MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")]
    public void ShouldFailOnLocalDecodeWhenTokenFooterIsInvalid(ProtocolVersion version, string token, string footer)
    {
        var result = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
            .AddFooter(footer)
            .Decode(token);

        result.IsValid.ShouldBe(false);
        result.Exception.ShouldNotBeNull();
    }

    // TODO: Public Decode fails tests, include invalid header v1.remote.

    [Theory(DisplayName = "Should fail on Local Decode when Token's Footer is not valid")]
    [InlineData(ProtocolVersion.V1, "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}")]
    [InlineData(ProtocolVersion.V2, "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")]
    [InlineData(ProtocolVersion.V3, "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9", "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}")]
    [InlineData(ProtocolVersion.V4, "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")]
    public void ShouldSucceedOnDecodeHeaderAndFooterOnly(ProtocolVersion version, string token, string expectedFooter)
    {
        var header = new PasetoBuilder().DecodeHeader(token);
        var footer = new PasetoBuilder().DecodeFooter(token);

        header.ShouldNotBeNullOrEmpty();
        header.ShouldBe($"v{(int)version}.local");
        footer.ShouldNotBeNullOrEmpty();
        footer.ShouldBe(expectedFooter);
    }

    [Theory(DisplayName = "Should throw exception on Decode when Token is missing")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void ShouldThrowExceptionOnDecodeWhenTokenIsMissing(string token)
    {
        Action act = () => new PasetoBuilder().Decode(token);

        // https://github.com/shouldly/shouldly/issues/392
        var ex = act.ShouldThrow<ArgumentNullException>();
        ex.ParamName.ShouldBe("token");
    }

    [Theory(DisplayName = "Should succeed on Encode to PARSEK when is Local Purpose and Symmetric Key")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldSucceedOnEncodeToParsekWhenIsLocalPurposeAndSymmetricKey(ProtocolVersion version)
    {
        var parsek = new PasetoBuilder().Use(version, Purpose.Local)
            .WithKey(CryptoBytes.FromHexString(LocalKey), Encryption.SymmetricKey)
            .GenerateSerializedKey(PaserkType.Local);

        parsek.ShouldStartWith($"k{(int)version}.local");
        parsek.Split('.').Length.ShouldBe(3);
    }

    [Theory(DisplayName = "Should succeed on Encode to PARSEK when is Local Purpose and Shared Key")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldSucceedOnEncodeToParsekWhenIsLocalPurposeAndSharedKey(ProtocolVersion version)
    {
        var parsek = new PasetoBuilder().Use(version, Purpose.Local)
            .WithSharedKey(CryptoBytes.FromHexString(LocalKey))
            .GenerateSerializedKey(PaserkType.Local);

        parsek.ShouldStartWith($"k{(int)version}.local");
        parsek.Split('.').Length.ShouldBe(3);
    }

    [Theory(DisplayName = "Should succeed on Encode to PARSEK when is Public Purpose and Public Asymmetric Key")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldSucceedOnEncodeToParsekWhenIsPublicPurposeAndPublicAsymmetricKey(ProtocolVersion version)
    {
        var keyLength = version switch
        {
            ProtocolVersion.V1 => 270,
            ProtocolVersion.V2 => 32,
            ProtocolVersion.V3 => 49,
            ProtocolVersion.V4 => 32,
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };

        var key = new byte[keyLength];
        RandomNumberGenerator.Fill(key);

        var parsek = new PasetoBuilder().Use(version, Purpose.Public)
            .WithKey(key, Encryption.AsymmetricPublicKey)
            .GenerateSerializedKey(PaserkType.Public);

        parsek.ShouldStartWith($"k{(int)version}.public");
        parsek.Split('.').Length.ShouldBe(3);
    }

    [Theory(DisplayName = "Should succeed on Encode to PARSEK when is Public Purpose and Secret Asymmetric Key")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldSucceedOnEncodeToParsekWhenIsPublicPurposeAndSecretAsymmetricKey(ProtocolVersion version)
    {
        var keyLength = version switch
        {
            ProtocolVersion.V1 => 1180,
            ProtocolVersion.V2 => 64,
            ProtocolVersion.V3 => 48,
            ProtocolVersion.V4 => 64,
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };

        var key = new byte[keyLength];
        RandomNumberGenerator.Fill(key);

        var parsek = new PasetoBuilder().Use(version, Purpose.Public)
            .WithKey(key, Encryption.AsymmetricSecretKey)
            .GenerateSerializedKey(PaserkType.Secret);

        parsek.ShouldStartWith($"k{(int)version}.secret");
        parsek.Split('.').Length.ShouldBe(3);
    }

    [Theory(DisplayName = "Should succeed on Decoding with Date Validations")]
    [MemberData(nameof(AllVersionsData), MemberType = typeof(TestHelper))]
    public void ShouldSucceedOnDecodingWithDateValidations(ProtocolVersion version)
    {
        const Purpose purpose = Purpose.Public;
        var keyLength = version switch
        {
            ProtocolVersion.V1 => 0,
            ProtocolVersion.V2 => 32,
            ProtocolVersion.V3 => 32,
            ProtocolVersion.V4 => 32,
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };

        var sharedKey = new byte[keyLength];
        RandomNumberGenerator.Fill(sharedKey);

        var keyPair = new PasetoBuilder()
            .Use(version, purpose)
            .GenerateAsymmetricKeyPair(sharedKey);

        var now = DateTime.UtcNow;

        var encoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithSecretKey([.. keyPair.SecretKey.Key.Span])
            .NotBefore(now)
            .IssuedAt(now.AddSeconds(-10))
            .Expiration(now.AddHours(1))
            .Encode();

        var validationParameters = new PasetoTokenValidationParameters
        {
            ValidateLifetime = true
        };

        var decoded = new PasetoBuilder()
            .Use(version, purpose)
            .WithPublicKey([.. keyPair.PublicKey.Key.Span])
            .Decode(encoded, validationParameters);

        decoded.IsValid.ShouldBe(true);
    }

    public static TheoryData<ProtocolVersion, byte[]> VersionsAndInvalidKeyData()
    {
        var bytes = new List<byte[]>
        {
            null,
            Array.Empty<byte>(),
            new byte[] { 0x80, 0x00 }
        };

        var ret = new TheoryData<ProtocolVersion, byte[]>();

        foreach (var version in Enum.GetValues<ProtocolVersion>())
        foreach (var key in bytes)
            ret.Add(version, key);

        return ret;
    }

    public static TheoryData<ProtocolVersion, byte[]> VersionsAndInvalidSeedData()
    {
        var bytes = new List<byte[]>
        {
            null,
            Array.Empty<byte>(),
            new byte[] { 0x80, 0x00 },
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

        var ret = new TheoryData<ProtocolVersion, byte[]>();

        foreach (var version in Enum.GetValues<ProtocolVersion>().Where(x => x != ProtocolVersion.V1))
        foreach (var key in bytes)
            ret.Add(version, key);

        return ret;
    }
}
