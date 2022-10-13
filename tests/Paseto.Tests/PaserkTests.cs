﻿namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using FluentAssertions;
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

    private static readonly ProtocolVersion[] ValidProtocols = new[]
    {
        ProtocolVersion.V1,
        ProtocolVersion.V2,
        ProtocolVersion.V3,
        ProtocolVersion.V4,
    };

    private static readonly PaserkType[] SupportedPaserkTypes = new[]
    {
        PaserkType.Local,
        PaserkType.Public,
        PaserkType.Secret,
    };

    private static readonly PaserkType[] PaserkIdTypes = new[]
    {
        PaserkType.Lid,
        PaserkType.Pid,
        PaserkType.Sid,
    };

    // TODO: Construct dynamically when supporting all types
    public static IEnumerable<object[]> Data()
    {
        foreach (var version in ValidProtocols)
        {
            foreach (var type in SupportedPaserkTypes)
            {
                yield return new object[] { version, type };
            }
        }
    }

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
                    yield return new object[] { test, version, type };
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

            act.Should().Throw<Exception>();
            return;
        }

        var purpose = Paserk.GetCompatibility(type);
        var pasetoKey = ParseKey(version, type, test.Key);

        var paserk = Paserk.Encode(pasetoKey, type);
        paserk.Should().Be(test.Paserk);

        var decodedPasetoKey = Paserk.Decode(test.Paserk);
        decodedPasetoKey.Should().NotBeNull();
        decodedPasetoKey.Key.IsEmpty.Should().BeFalse();
        decodedPasetoKey.Key.Span.ToArray().Should().BeEquivalentTo(TestHelper.ReadKey(test.Key));
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

            act.Should().Throw<Exception>();
            return;
        }

        var purpose = Paserk.GetCompatibility(type);
        var pasetoKey = ParseKey(version, type, test.Key);

        var paserk = Paserk.Encode(pasetoKey, type);
        paserk.Should().Be(test.Paserk);
    }

    public static IEnumerable<object[]> PwGenerator => TestItemGenerator(new ProtocolVersion[] { ProtocolVersion.V1, ProtocolVersion.V2, ProtocolVersion.V3, ProtocolVersion.V4 }, new PaserkType[] { PaserkType.LocalPassword, PaserkType.SecretPassword });

    [Theory]
    [MemberData(nameof(PwGenerator))]
    public void TestPwVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
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
                Paserk.Decode(test.Paserk, test.Password);
            };

            act.Should().Throw<Exception>();
            return;
        }

        var purpose = Paserk.GetCompatibility(type);
        var pasetoKey = ParseKey(version, type, test.Unwrapped);

        // Decode paserk to verify decoding works
        var decoded = Paserk.Decode(test.Paserk, test.Password);
        decoded.Key.Span.ToArray().Should().BeEquivalentTo(pasetoKey.Key.ToArray());

        // Encode then decode to verify that encoding works
        var wrapped = version switch
        {
            ProtocolVersion.V1 or ProtocolVersion.V3 => Paserk.Encode(pasetoKey, type, test.Password, test.Options["iterations"]),
            // Lower the memorycost and ops to reduce run time.
            ProtocolVersion.V2 or ProtocolVersion.V4 => Paserk.Encode(pasetoKey, type, test.Password, test.Options["memlimit"] / (16 * 1024), test.Options["opslimit"] - 1, 1),
            _ => throw new NotImplementedException(),
        };

        var unwrapped = Paserk.Decode(wrapped, test.Password);
        unwrapped.Key.Span.ToArray().Should().BeEquivalentTo(pasetoKey.Key.ToArray());
    }

    [Theory]
    [MemberData(nameof(Data))]
    public void PaserkTypeShouldNotEncodeIncompatibleKey(ProtocolVersion version, PaserkType type)
    {
        var json = GetPaserkTestVector((int)version, type.ToDescription());

        var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);

        var test = vector.Tests.First();
        var purpose = Paserk.GetCompatibility(type);

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
            act.Should().Throw<Exception>();
        }
    }

    private static PasetoKey ParseKey(ProtocolVersion version, PaserkType type, string key)
    {
        switch (type)
        {
            case PaserkType.LocalWrap:

            case PaserkType.Seal:

            case PaserkType.Local or PaserkType.Lid or PaserkType.LocalPassword:
                return new PasetoSymmetricKey(CryptoBytes.FromHexString(key), Paserk.CreateProtocolVersion(version));

            case PaserkType.SecretWrap:
                break;

            case PaserkType.Secret or PaserkType.Sid or PaserkType.SecretPassword:
                return new PasetoAsymmetricSecretKey(TestHelper.ReadKey(key), Paserk.CreateProtocolVersion(version));

            case PaserkType.Public or PaserkType.Pid:
                return new PasetoAsymmetricPublicKey(TestHelper.ReadKey(key), Paserk.CreateProtocolVersion(version));

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