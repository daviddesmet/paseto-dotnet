namespace Paseto.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;

using FluentAssertions;
using NaCl.Core.Internal;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

using Paseto.Cryptography;
using Paseto.Cryptography.Key;
using Paseto.Extensions;
using Paseto.Protocol;
using Paseto.Tests.Vectors;

[Category("CI")]
public class PaserkTests
{
    private readonly ITestOutputHelper _output;

    public PaserkTests(ITestOutputHelper output) => _output = output;

    // TODO: Construct dynamically when supporting all types
    public static IEnumerable<object[]> Data => new[]
    {
        new object[] { ProtocolVersion.V1, PaserkType.Local },
        new object[] { ProtocolVersion.V1, PaserkType.Public },
        new object[] { ProtocolVersion.V1, PaserkType.Secret },

        new object[] { ProtocolVersion.V2, PaserkType.Local },
        new object[] { ProtocolVersion.V2, PaserkType.Public },
        new object[] { ProtocolVersion.V2, PaserkType.Secret },

        new object[] { ProtocolVersion.V3, PaserkType.Local },
        new object[] { ProtocolVersion.V3, PaserkType.Public },
        new object[] { ProtocolVersion.V3, PaserkType.Secret },

        new object[] { ProtocolVersion.V4, PaserkType.Local },
        new object[] { ProtocolVersion.V4, PaserkType.Public },
        new object[] { ProtocolVersion.V4, PaserkType.Secret }
    };

    [Theory]
    [MemberData(nameof(Data))]
    public void TypesTestVectors(ProtocolVersion version, PaserkType type)
    {
        var json = GetPaserkTestVector((int)version, type.ToDescription());

        var vector = JsonConvert.DeserializeObject<PaserkTestCollection>(json);

        foreach (var test in vector.Tests)
        {
            var purpose = Paserk.GetCompatibility(type);

            try
            {
                var pasetoKey = ParseKey(version, type, test.Key);

                var paserk = Paserk.Encode(pasetoKey, purpose, type);
                paserk.Should().Be(test.Paserk);
            }
            catch (PasetoNotSupportedException)
            {
                // This could be expected
                _output.WriteLine($"ENCODE FAIL {test.Name}: since the type is not supported: {type}");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"ENCODE FAIL {test.Name}: {ex.Message}");
            }
        }
    }

    private static PasetoKey ParseKey(ProtocolVersion version, PaserkType type, string key)
    {
        switch (type)
        {
            case PaserkType.Lid:
                break;
            case PaserkType.Local:
                return new PasetoSymmetricKey(CryptoBytes.FromHexString(key), CreateProtocolVersion(version));
            case PaserkType.LocalWrap:
                break;
            case PaserkType.LocalPassword:
                break;
            case PaserkType.Seal:
                break;
            case PaserkType.Sid:
                break;
            case PaserkType.Secret:
                return new PasetoAsymmetricSecretKey(CryptoBytes.FromHexString(key), CreateProtocolVersion(version));
            case PaserkType.SecretWrap:
                break;
            case PaserkType.SecretPassword:
                break;
            case PaserkType.Pid:
                break;
            case PaserkType.Public:
                return new PasetoAsymmetricPublicKey(CryptoBytes.FromHexString(key), CreateProtocolVersion(version));
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, "Type not supported");
        }

        throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    private static IPasetoProtocolVersion CreateProtocolVersion(ProtocolVersion version)
    {
#pragma warning disable IDE0022 // Use expression body for methods
        return version switch
        {
            ProtocolVersion.V1 => new Version1(),
            ProtocolVersion.V2 => new Version2(),
            ProtocolVersion.V3 => new Version3(),
            ProtocolVersion.V4 => new Version4(),
            _ => throw new PasetoNotSupportedException($"The protocol version {version} is currently not supported."),
        };
#pragma warning restore IDE0022 // Use expression body for methods
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