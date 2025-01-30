namespace Paseto.Tests;

using System;
using System.IO;
using System.Linq;
using System.Net.Http;

using Shouldly;
using NaCl.Core.Internal;
using Newtonsoft.Json;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

using Builder;
using Cryptography;
using Vectors;

using static TestHelper;

[Category("CI")]
public class PasetoTestVectors
{
    private readonly string[] SKIP_ASSERT_ENCODE = { "v1" };

    private readonly ITestOutputHelper _output;

    public PasetoTestVectors(ITestOutputHelper output) => _output = output;

    [Theory]
    [MemberData(nameof(VersionStringNameData), MemberType = typeof(TestHelper))]
    public void VersionTestVectors(string version)
    {
        var json = GetPasetoTestVector(version);

        var vector = JsonConvert.DeserializeObject<PasetoTestCollection>(json);

        var errors = 0;
        foreach (var test in vector.Tests)
        {
            /*
             * Encode
             */
            var builder = new PasetoBuilder();

            // expect-fail is only for decoding tests
            if (!test.ExpectFail)
            {
                if (test.IsLocal)
                {
                    builder = builder.Use(version, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey)
                                     .WithNonce(CryptoBytes.FromHexString(test.Nonce));
                }
                else
                {
                    if (version == "v2" || version == "v4")
                    {
                        // We assert the seed since we want them to fail in case it changes
                        var secretKey = CryptoBytes.ToHexStringLower(Ed25519.ExpandedPrivateKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                        secretKey.ShouldBe(test.SecretKey);

                        var publicKey = CryptoBytes.ToHexStringLower(Ed25519.PublicKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                        publicKey.ShouldBe(test.PublicKey);
                    }

                    builder = builder.Use(version, Purpose.Public)
                                     .WithKey(ReadKey(test.SecretKey), Encryption.AsymmetricSecretKey);
                }

                if (!string.IsNullOrEmpty(test.Payload))
                {
                    var testPayload = JsonConvert.DeserializeObject<PasetoTestPayload>(test.Payload, new JsonSerializerSettings
                    {
                        DateTimeZoneHandling = DateTimeZoneHandling.Utc
                    });

                    builder.AddClaim("data", testPayload.Data);
                    builder.AddClaim("exp", testPayload.ExpString);
                    //builder.AddClaim(RegisteredClaims.ExpirationTime, payload.Exp);
                }

                if (!string.IsNullOrEmpty(test.Footer))
                    builder.AddFooter(test.Footer);

                if (!string.IsNullOrEmpty(test.ImplicitAssertion))
                    builder.AddImplicitAssertion(test.ImplicitAssertion);

                try
                {
                    var token = builder.Encode();

                    if (SKIP_ASSERT_ENCODE.Contains(version) && test.IsPublic)
                    {
                        // The generated token is always different, so we just validate it can actually be decoded
                        builder = builder.Use(version, Purpose.Public)
                                         .WithKey(ReadKey(test.PublicKey), Encryption.AsymmetricPublicKey);

                        var result = builder.Decode(token);

                        result.Paseto.RawPayload.ShouldBe(test.Payload);
                    }
                    else
                    {
                        token.ShouldBe(test.Token);
                    }
                }
                catch (PasetoNotSupportedException)
                {
                    // This could be expected
                    _output.WriteLine($"ENCODE FAIL {test.Name}: since the protocol version is not supported: {builder.DecodeHeader(test.Token)}");
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"ENCODE FAIL {test.Name}: {ex.Message}");
                }
            }

            /*
             * Decode
             */
            builder = new PasetoBuilder();

            if (test.ExpectFail)
            {
                // Tests may have mixed combination of purpose (based on the token) and keys. E.g. Local with Asymmetric keys or Public with Symmetric Keys

                if (!string.IsNullOrEmpty(test.Key))
                {
                    // Using Symmetric Key
                    builder = builder.Use(version, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey);
                }
                else
                {
                    // Using Asymmetric Key
                    builder = builder.Use(version, Purpose.Public)
                                     .WithKey(ReadKey(test.PublicKey), Encryption.AsymmetricPublicKey);
                }
            }
            else
            {
                if (test.IsLocal)
                {
                    builder = builder.Use(version, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey);
                }
                else
                {
                    builder = builder.Use(version, Purpose.Public)
                                     .WithKey(ReadKey(test.PublicKey), Encryption.AsymmetricPublicKey);
                }
            }

            if (!string.IsNullOrEmpty(test.Footer))
                builder.AddFooter(test.Footer);

            if (!string.IsNullOrEmpty(test.ImplicitAssertion))
                builder.AddImplicitAssertion(test.ImplicitAssertion);

            try
            {
                var result = builder.Decode(test.Token);

                result.IsValid.ShouldBe(!test.ExpectFail);

                if (test.ExpectFail)
                    errors++;
                else
                    result.Paseto.RawPayload.ShouldBe(test.Payload);
            }
            catch (PasetoNotSupportedException)
            {
                // This could be expected
                _output.WriteLine($"DECODE FAIL {test.Name}: since the protocol version is not supported: {builder.DecodeHeader(test.Token)}");
            }
            //catch (PasetoInvalidException)
            //{
            //    errors++;
            //    test.ExpectFail.Should().BeTrue();
            //}
            //catch (PasetoVerificationException)
            //{
            //    errors++;
            //    test.ExpectFail.Should().BeTrue();
            //}
            catch (Exception ex)
            {
                errors++;
                if (test.ExpectFail)
                    _output.WriteLine($"DECODE FAIL {test.Name}: which was expected, with an exception of: {ex.GetType().Name}");
                else
                    _output.WriteLine($"DECODE FAIL {test.Name}: {ex.Message}");
            }
        }

        errors.ShouldBe(vector.Tests.Count(t => t.ExpectFail));
    }

    private static string GetPasetoTestVector(string version)
    {
        try
        {
            using var client = new HttpClient();
            return client.GetStringAsync($"https://github.com/paseto-standard/test-vectors/raw/master/{version}.json").Result;
        }
        catch (Exception)
        {
            return File.ReadAllText($@"Vectors\{version}.json");
        }
    }
}
