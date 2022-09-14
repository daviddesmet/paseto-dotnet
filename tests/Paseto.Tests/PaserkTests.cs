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

    public static IEnumerable<object[]> PaserkTestItems()
    {
        foreach (var val in Data())
        {
            var version = (ProtocolVersion) val[0] ;
            var type = (PaserkType) val[1];

            var json = GetPaserkTestVector((int)version, type.ToDescription());

            var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);
            foreach (var test in vector.Tests)
            {
                yield return new object[] { test, version, type };
            }
        }
    }

    [Theory]
    [MemberData(nameof(PaserkTestItems))]
    public void TypesTestVectors(PaserkTestItem test, ProtocolVersion version, PaserkType type)
    {
        if (test.ExpectFail)
        {
            var act = () => Paserk.Decode(test.Paserk);
            act.Should().Throw<Exception>();
            return;
        }

        var purpose = Paserk.GetCompatibility(type);
        var pasetoKey = ParseKey(version, type, test.Key);

        var paserk = Paserk.Encode(pasetoKey, purpose, type);
        paserk.Should().Be(test.Paserk);

        var decodedPasetoKey = Paserk.Decode(test.Paserk);
        decodedPasetoKey.Should().NotBeNull();
        decodedPasetoKey.Key.IsEmpty.Should().BeFalse();
        decodedPasetoKey.Key.Span.ToArray().Should().BeEquivalentTo(CryptoBytes.FromHexString(test.Key));
    }

    [Theory]
    [MemberData(nameof(Data))]
    public void TypesTestVectorsShouldFail(ProtocolVersion version, PaserkType type)
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
            var act = () => Paserk.Encode(pasetoKey, purpose, incompatibleType);
            act.Should().Throw<Exception>();
        }
    }

    private static PasetoKey ParseKey(ProtocolVersion version, PaserkType type, string key)
    {
        switch (type)
        {
            case PaserkType.Lid:
                break;

            case PaserkType.Local:
                return new PasetoSymmetricKey(CryptoBytes.FromHexString(key), Paserk.CreateProtocolVersion(version));

            case PaserkType.LocalWrap:

            case PaserkType.LocalPassword:

            case PaserkType.Seal:

            case PaserkType.Sid:
                break;

            case PaserkType.Secret:
                return new PasetoAsymmetricSecretKey(CryptoBytes.FromHexString(key), Paserk.CreateProtocolVersion(version));

            case PaserkType.SecretWrap:
                break;

            case PaserkType.SecretPassword:
                break;

            case PaserkType.Pid:
                break;

            case PaserkType.Public:
                return new PasetoAsymmetricPublicKey(CryptoBytes.FromHexString(key), Paserk.CreateProtocolVersion(version));

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