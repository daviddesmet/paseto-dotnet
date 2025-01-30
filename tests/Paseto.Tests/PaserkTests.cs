namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;

using Shouldly;
using NaCl.Core.Internal;
using Newtonsoft.Json;
using Paseto.Cryptography.Key;
using Paseto.Extensions;
using Paseto.Tests.Vectors;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

[Category("CI")]
public class PaserkTests
{
    private readonly ITestOutputHelper _output;

    public PaserkTests(ITestOutputHelper output) => _output = output;

    private static readonly ProtocolVersion[] ValidProtocols = Enum.GetValues<ProtocolVersion>();

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

    private static PasetoKey ParseKey(ProtocolVersion version, PaserkType type, string key)
    {
        switch (type)
        {
            case PaserkType.Local or PaserkType.Lid:
                return new PasetoSymmetricKey(CryptoBytes.FromHexString(key), PaserkHelpers.CreateProtocolVersion(version));
            case PaserkType.LocalWrap:
            case PaserkType.LocalPassword:
            case PaserkType.Seal:
            case PaserkType.Secret or PaserkType.Sid:
                return new PasetoAsymmetricSecretKey(TestHelper.ReadKey(key), PaserkHelpers.CreateProtocolVersion(version));
            case PaserkType.SecretWrap:
                break;
            case PaserkType.SecretPassword:
                break;
            case PaserkType.Public or PaserkType.Pid:
                return new PasetoAsymmetricPublicKey(TestHelper.ReadKey(key), PaserkHelpers.CreateProtocolVersion(version));
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, "Type not supported");
        }

        throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
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