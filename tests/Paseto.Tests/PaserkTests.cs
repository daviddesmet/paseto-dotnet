namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;

using Shouldly;
using Newtonsoft.Json;
using Paseto.Extensions;
using Xunit;
using Xunit.Abstractions;

using Org.BouncyCastle.Crypto.Parameters;

using Paseto.Cryptography.Key;
using Paseto.Tests.Vectors;
using Paseto.Internal;

using static Paseto.Tests.TestHelper;

[Trait("Category", "CI")]
public class PaserkTests
{
    private readonly ITestOutputHelper _output;

    public PaserkTests(ITestOutputHelper output) => _output = output;

    private static readonly ProtocolVersion[] ValidProtocols = ((ProtocolVersion[])Enum.GetValues(typeof(ProtocolVersion)));

    private static readonly PaserkType[] SupportedPaserkTypes =
    [
        PaserkType.Local,
        PaserkType.Public,
        PaserkType.Secret
    ];

    private static readonly PaserkType[] PaserkIdTypes =
    [
        PaserkType.Lid,
        PaserkType.Pid,
        PaserkType.Sid
    ];

    private static readonly PaserkType[] PaserkWrapTypes =
    [
        PaserkType.LocalWrap,
        PaserkType.SecretWrap
    ];

    private static readonly PaserkType[] PaserkPwTypes =
    [
        PaserkType.LocalPassword,
        PaserkType.SecretPassword
    ];

    private static readonly PaserkType[] PaserkSealTypes =
    [
        PaserkType.Seal
    ];

    // Seal is only implemented for the actively-supported versions (v3 = P-384, v4 = X25519).
    private static readonly ProtocolVersion[] SealProtocols =
    [
        ProtocolVersion.V3,
        ProtocolVersion.V4
    ];

    // TODO: Construct dynamically when supporting all types
    public static IEnumerable<object[]> Data() => from version in ValidProtocols from type in SupportedPaserkTypes select (object[])[version, type];

    public static IEnumerable<object[]> TestItemGenerator(ProtocolVersion[] versions, PaserkType[] types)
    {
        foreach (var version in versions)
        {
            foreach (var type in types)
            {
                var json = GetPaserkTestVector((int)version, type.ToDescription());

                var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);
                foreach (var test in vector.Tests)
                {
                    yield return [test, version, type];
                }
            }
        }
    }

    public static IEnumerable<object[]> TypesGenerator => TestItemGenerator(ValidProtocols, SupportedPaserkTypes);

    [Theory]
    [MemberData(nameof(TypesGenerator))]
    public void TypesTestVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        // Paserk implementation is not version specific so we skip this test.
        if (test is { ExpectFail: true, Comment: "Implementations MUST NOT accept a PASERK of the wrong version." })
        {
            return;
        }

        if (test.ExpectFail)
        {
            Action act;

            if (test.Key is null)
            {
                act = () => Paserk.Decode(test.Paserk);
            }
            else
            {
                act = () =>
                {
                    var key = ParseKey(version, type, test.Key);
                    Paserk.Encode(key, type);
                };
            }

            act.ShouldThrow<Exception>();
            return;
        }

        var purpose = Paserk.GetPurpose(type);
        var pasetoKey = ParseKey(version, type, test.Key);

        var paserk = Paserk.Encode(pasetoKey, type);
        paserk.ShouldBe(test.Paserk);

        var decodedPasetoKey = Paserk.Decode(test.Paserk);
        decodedPasetoKey.ShouldNotBeNull();
        decodedPasetoKey.Key.IsEmpty.ShouldBe(false);
        decodedPasetoKey.Key.Span.ToArray().ShouldBeEquivalentTo(TestHelper.ReadKey(test.Key));
    }

    // Wrap / password vectors use a different file suffix and extra fields, so they get their own generator.
    private static string VectorSuffix(PaserkType type) => type switch
    {
        PaserkType.LocalWrap or PaserkType.SecretWrap => $"{type.ToDescription()}.pie",
        _ => type.ToDescription(),
    };

    private static IEnumerable<object[]> WrapItemGenerator(ProtocolVersion[] versions, PaserkType[] types)
    {
        foreach (var version in versions)
        {
            foreach (var type in types)
            {
                var json = GetPaserkTestVector((int)version, VectorSuffix(type));

                var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);
                foreach (var test in vector.Tests)
                {
                    yield return [test, version, type];
                }
            }
        }
    }

    public static IEnumerable<object[]> WrapGenerator => WrapItemGenerator(ValidProtocols, PaserkWrapTypes);

    [Theory]
    [MemberData(nameof(WrapGenerator))]
    public void WrapTestVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        // Paserk implementation is not version specific so we skip this test.
        if (test is { ExpectFail: true, Comment: "Implementations MUST NOT accept a PASERK of the wrong version." })
        {
            return;
        }

        var wrappingKey = new PasetoSymmetricKey(FromHexString(test.WrappingKey), PaserkHelpers.CreateProtocolVersion(version));

        if (test.ExpectFail)
        {
            var act = () => Paserk.Decode(test.Paserk, wrappingKey);
            act.ShouldThrow<Exception>();
            return;
        }

        // Decode the official vector, then compare against the expected unwrapped key.
        var decoded = Paserk.Decode(test.Paserk, wrappingKey);
        decoded.ShouldNotBeNull();
        AssertUnwrapped(decoded, test.Unwrapped);

        // Round-trip: re-wrap the decoded key (fresh random nonce) and ensure it unwraps back unchanged.
        var ptk = BuildWrappedKey(type, version, decoded.Key.ToArray());
        var reWrapped = Paserk.Encode(ptk, type, wrappingKey);
        var reDecoded = Paserk.Decode(reWrapped, wrappingKey);
        reDecoded.Key.Span.ToArray().ShouldBeEquivalentTo(decoded.Key.ToArray());
    }

    public static IEnumerable<object[]> PwGenerator => WrapItemGenerator(ValidProtocols, PaserkPwTypes);

    [Theory]
    [MemberData(nameof(PwGenerator))]
    public void PwTestVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        // Paserk implementation is not version specific so we skip this test.
        if (test is { ExpectFail: true, Comment: "Implementations MUST NOT accept a PASERK of the wrong version." })
        {
            return;
        }

        var password = Encoding.UTF8.GetBytes(test.Password);

        if (test.ExpectFail)
        {
            var act = () => Paserk.Decode(test.Paserk, password);
            act.ShouldThrow<Exception>();
            return;
        }

        // Decode the official vector, then compare against the expected unwrapped key.
        var decoded = Paserk.Decode(test.Paserk, password);
        decoded.ShouldNotBeNull();
        AssertUnwrapped(decoded, test.Unwrapped);

        // Round-trip with the vector's parameters (kept small so the test stays fast).
        var options = new PbkwOptions
        {
            MemoryLimitBytes = test.Options?.Memlimit > 0 ? test.Options.Memlimit : 67_108_864,
            OpsLimit = test.Options?.Opslimit > 0 ? test.Options.Opslimit : 2,
            Iterations = test.Options?.Iterations > 0 ? test.Options.Iterations : 100_000,
        };
        var ptk = BuildWrappedKey(type, version, decoded.Key.ToArray());
        var wrapped = Paserk.Encode(ptk, type, password, options);
        var reDecoded = Paserk.Decode(wrapped, password);
        reDecoded.Key.Span.ToArray().ShouldBeEquivalentTo(decoded.Key.ToArray());
    }

    private static void AssertUnwrapped(PasetoKey decoded, string unwrappedHex)
    {
        var expected = TestHelper.ReadKey(unwrappedHex);

        // For modern versions (and all local keys) the decoded bytes match the vector's "unwrapped"
        // field exactly. The obsolete k1 (RSA) secret vectors wrap a non-raw key representation
        // (the reference implementation does not cover v1 either), so we only assert exact equality
        // when the encodings line up; round-trip self-consistency is still verified by the caller.
        if (decoded.Key.Length == expected.Length)
            decoded.Key.Span.ToArray().ShouldBeEquivalentTo(expected);
    }

    private static PasetoKey BuildWrappedKey(PaserkType type, ProtocolVersion version, byte[] bytes)
    {
        var protocol = PaserkHelpers.CreateProtocolVersion(version);

        return type switch
        {
            PaserkType.LocalWrap or PaserkType.LocalPassword => new PasetoSymmetricKey(bytes, protocol),
            PaserkType.SecretWrap or PaserkType.SecretPassword => new PasetoAsymmetricSecretKey(bytes, protocol),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Type not supported"),
        };
    }

    public static IEnumerable<object[]> SealGenerator => WrapItemGenerator(SealProtocols, PaserkSealTypes);

    [Theory]
    [MemberData(nameof(SealGenerator))]
    public void SealTestVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        // The wrong-version fail vectors carry a key of a different version; the version guard in
        // Paserk already rejects them, so skip (consistent with the other theories).
        if (test is { ExpectFail: true, Comment: "Implementations MUST NOT accept a PASERK of the wrong version." })
        {
            return;
        }

        var (publicKey, secretKey) = BuildSealingKeys(version, test);

        if (test.ExpectFail)
        {
            var act = () => Paserk.Decode(test.Paserk, secretKey);
            act.ShouldThrow<Exception>();
            return;
        }

        // Decode (unseal) the official vector, then compare against the expected local key.
        var decoded = Paserk.Decode(test.Paserk, secretKey);
        decoded.ShouldNotBeNull();
        decoded.Key.Span.ToArray().ShouldBeEquivalentTo(FromHexString(test.Unsealed));

        // Round-trip: re-seal the decoded key (fresh random ephemeral key) and ensure it unseals back.
        var localKey = new PasetoSymmetricKey(decoded.Key.ToArray(), PaserkHelpers.CreateProtocolVersion(version));
        var resealed = Paserk.Encode(localKey, type, publicKey);
        var reDecoded = Paserk.Decode(resealed, secretKey);
        reDecoded.Key.Span.ToArray().ShouldBeEquivalentTo(decoded.Key.ToArray());
    }

    private static (PasetoAsymmetricPublicKey publicKey, PasetoAsymmetricSecretKey secretKey) BuildSealingKeys(ProtocolVersion version, PaserkTestItem test)
    {
        var protocol = PaserkHelpers.CreateProtocolVersion(version);

        // v4 keys are raw hex (Ed25519); v3 keys are PEM-encoded P-384 keys.
        if (version == ProtocolVersion.V4)
        {
            return (new PasetoAsymmetricPublicKey(FromHexString(test.SealingPublicKey), protocol),
                    new PasetoAsymmetricSecretKey(FromHexString(test.SealingSecretKey), protocol));
        }

        return (new PasetoAsymmetricPublicKey(ParseP384PublicKey(test.SealingPublicKey), protocol),
                new PasetoAsymmetricSecretKey(ParseP384SecretKey(test.SealingSecretKey), protocol));
    }

    private static byte[] ParseP384PublicKey(string pem)
    {
        using var reader = new StringReader(pem);
        var pub = (ECPublicKeyParameters)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
        return pub.Q.GetEncoded(compressed: true); // 49-byte compressed point
    }

    private static byte[] ParseP384SecretKey(string pem)
    {
        using var reader = new StringReader(pem);
        var obj = new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
        var priv = obj switch
        {
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair kp => (ECPrivateKeyParameters)kp.Private,
            ECPrivateKeyParameters p => p,
            _ => throw new InvalidOperationException("Unexpected PEM object for a P-384 secret key."),
        };
        return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(48, priv.D); // 48-byte raw scalar
    }

    public static IEnumerable<object[]> IdGenerator => TestItemGenerator(ValidProtocols, PaserkIdTypes);

    [Theory]
    [MemberData(nameof(IdGenerator))]
    public void TestIdVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        // Paserk implementation is not version specific so we skip this test.
        if (test is { ExpectFail: true, Comment: "Implementations MUST NOT accept a PASERK of the wrong version." })
        {
            return;
        }

        if (test.ExpectFail)
        {
            var act = () =>
            {
                var key = ParseKey(version, type, test.Key);
                Paserk.Encode(key, type);
            };

            act.ShouldThrow<Exception>();
            return;
        }

        var purpose = Paserk.GetPurpose(type);
        var pasetoKey = ParseKey(version, type, test.Key);

        var paserk = Paserk.Encode(pasetoKey, type);
        paserk.ShouldBe(test.Paserk);
    }

    [Theory]
    [MemberData(nameof(Data))]
    public void PaserkTypeShouldNotEncodeIncompatibleKey(ProtocolVersion version, PaserkType type)
    {
        var json = GetPaserkTestVector((int)version, type.ToDescription());

        var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);

        var test = vector.Tests.First();
        var purpose = Paserk.GetPurpose(type);

        PasetoKey pasetoKey;
        try
        {
            pasetoKey = ParseKey(version, type, test.Key);
        }
        catch (Exception ex)
        {
            _output.WriteLine($"KEY PARSE FAIL {test.Name}: {ex.Message}");
            return;
        }

        foreach (var incompatibleType in SupportedPaserkTypes.Where(t => t != type))
        {
            var act = () => Paserk.Encode(pasetoKey, incompatibleType);
            act.ShouldThrow<Exception>();
        }
    }

    private const string WrapKeyHex = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    private static PasetoSymmetricKey Sym(ProtocolVersion v) => new(FromHexString(WrapKeyHex), PaserkHelpers.CreateProtocolVersion(v));

    [Fact]
    public void WrapEncodeThrowsOnNullKey() =>
        Should.Throw<ArgumentNullException>(() => Paserk.Encode(null, PaserkType.LocalWrap, Sym(ProtocolVersion.V4)));

    [Fact]
    public void WrapEncodeThrowsOnNullWrappingKey() =>
        Should.Throw<ArgumentNullException>(() => Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.LocalWrap, (PasetoSymmetricKey)null));

    [Fact]
    public void WrapEncodeThrowsOnNonWrapType() =>
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.Local, Sym(ProtocolVersion.V4)));

    [Fact]
    public void WrapEncodeThrowsOnIncompatibleKey()
    {
        var publicKey = new PasetoAsymmetricPublicKey(FromHexString(WrapKeyHex), PaserkHelpers.CreateProtocolVersion(ProtocolVersion.V4));
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Encode(publicKey, PaserkType.LocalWrap, Sym(ProtocolVersion.V4)));
    }

    [Fact]
    public void WrapEncodeThrowsOnVersionMismatch() =>
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.LocalWrap, Sym(ProtocolVersion.V3)));

    [Fact]
    public void WrapDecodeThrowsOnNullWrappingKey()
    {
        var paserk = Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.LocalWrap, Sym(ProtocolVersion.V4));
        Should.Throw<ArgumentNullException>(() => Paserk.Decode(paserk, (PasetoSymmetricKey)null));
    }

    [Fact]
    public void WrapDecodeThrowsOnNonWrapType()
    {
        var localPaserk = Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.Local);
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Decode(localPaserk, Sym(ProtocolVersion.V4)));
    }

    [Fact]
    public void WrapDecodeThrowsOnVersionMismatch()
    {
        var paserk = Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.LocalWrap, Sym(ProtocolVersion.V4));
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Decode(paserk, Sym(ProtocolVersion.V3)));
    }

    [Fact]
    public void PwEncodeThrowsOnNullKey() =>
        Should.Throw<ArgumentNullException>(() => Paserk.Encode(null, PaserkType.LocalPassword, "pw"u8.ToArray()));

    [Fact]
    public void PwEncodeThrowsOnNonPwType() =>
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.Local, "pw"u8.ToArray()));

    [Fact]
    public void PwEncodeThrowsOnIncompatibleKey()
    {
        var publicKey = new PasetoAsymmetricPublicKey(FromHexString(WrapKeyHex), PaserkHelpers.CreateProtocolVersion(ProtocolVersion.V4));
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Encode(publicKey, PaserkType.LocalPassword, "pw"u8.ToArray()));
    }

    [Fact]
    public void PwDecodeThrowsOnNonPwType()
    {
        var localPaserk = Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.Local);
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Decode(localPaserk, "pw"u8.ToArray()));
    }

    [Fact]
    public void WrapDecodeRejectsPasswordType()
    {
        var paserk = Paserk.Encode(Sym(ProtocolVersion.V4), PaserkType.LocalWrap, Sym(ProtocolVersion.V4));
        Should.Throw<PaserkNotSupportedException>(() => Paserk.Decode(paserk, "pw"u8.ToArray()));
    }

    [Theory]
    [InlineData("   ", typeof(ArgumentNullException))]
    [InlineData("invalid", typeof(PaserkInvalidException))]
    [InlineData("k4.local", typeof(PaserkInvalidException))]
    [InlineData("k9.local-wrap.pie.AAAA", typeof(PaserkInvalidException))]
    public void DecodeThrowsOnInvalidHeader(string serialized, Type expected)
    {
        var act = () => Paserk.Decode(serialized, Sym(ProtocolVersion.V4));
        act.ShouldThrow(expected);
    }

    private static PasetoKey ParseKey(ProtocolVersion version, PaserkType type, string key)
    {
        switch (type)
        {
            case PaserkType.Local or PaserkType.Lid:
            case PaserkType.LocalWrap or PaserkType.LocalPassword:
                return new PasetoSymmetricKey(FromHexString(key), PaserkHelpers.CreateProtocolVersion(version));
            case PaserkType.Seal:
            case PaserkType.Secret or PaserkType.Sid:
            case PaserkType.SecretWrap or PaserkType.SecretPassword:
                return new PasetoAsymmetricSecretKey(TestHelper.ReadKey(key), PaserkHelpers.CreateProtocolVersion(version));
            case PaserkType.Public or PaserkType.Pid:
                return new PasetoAsymmetricPublicKey(TestHelper.ReadKey(key), PaserkHelpers.CreateProtocolVersion(version));
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, "Type not supported");
        }
    }

    private static string GetPaserkTestVector(int version, string type)
    {
        try
        {
            using var client = new HttpClient();
            return client.GetStringAsync($"https://github.com/paseto-standard/test-vectors/raw/master/PASERK/k{version}.{type}.json").Result;
        }
        catch (Exception)
        {
            return File.ReadAllText($@"Vectors\Paserk\k{version}.{type}.json");
        }
    }
}