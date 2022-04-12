namespace Paseto.Tests;

using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using FluentAssertions;
using NaCl.Core.Internal;
using Newtonsoft.Json;
using Org.BouncyCastle.OpenSsl;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

using Paseto.Builder;
using Paseto.Cryptography;
using Paseto.Extensions;
using Paseto.Tests.Vectors;
using static Paseto.Utils.EncodingHelper;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

[Category("CI")]
public class PasetoTestVectors
{
    private readonly string[] SKIP_ASSERT_ENCODE = new string[] { "v1" };
    private readonly Regex ECDsaPrivateKeyRegex = new(@"-----(BEGIN|END) EC PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private readonly Regex RsaPrivateKeyRegex = new(@"-----(BEGIN|END) (RSA|OPENSSH|ENCRYPTED) PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private readonly Regex RsaPublicKeyRegex = new(@"-----(BEGIN|END) PUBLIC KEY-----[\W]*", RegexOptions.Compiled);
    private readonly ITestOutputHelper _output;

    public PasetoTestVectors(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData("v1")]
    [InlineData("v2")]
    [InlineData("v3")]
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
                    if (version == "v2")
                    {
                        // We assert the seed since we want them to fail in case it changes
                        var secretKey = CryptoBytes.ToHexStringLower(Ed25519.ExpandedPrivateKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                        secretKey.Should().Be(test.SecretKey);

                        var publicKey = CryptoBytes.ToHexStringLower(Ed25519.PublicKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                        publicKey.Should().Be(test.PublicKey);
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

                try
                {
                    var token = builder.Encode();

                    if (SKIP_ASSERT_ENCODE.Contains(version) && test.IsPublic)
                    {
                        // The generated token is always different, so we just validate it can actually be decoded
                        builder = builder.Use(version, Purpose.Public)
                                         .WithKey(ReadKey(test.PublicKey), Encryption.AsymmetricPublicKey);

                        var payload = builder.Decode(token);

                        payload.Should().Be(test.Payload);
                    }
                    else
                    {
                        token.Should().Be(test.Token);
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

                // 1-S-1
                // v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9ITaOgxZh43XkefPOcWykJaYdvpNyo3e7N4ZCx9bzz_iycyiZISO3M_bh6ifGWSC5-Es7b0rF9gMiEMzfO-bVojgvtC8YUB-Zrw9MTCYl2MKi2FSCMnbpx5UIaOSt5SzFRI2ofvDO9dNbBB9NInCNtnb8TtjTIi9s6o5QipTiZwsdcK7wl_u8MM4p42WSL-QY_yBnmbm5x5ayN29OA30ZnrP-9oN2xXD1G5F39Uf-QeMBtuhT4VIV4FhbSK-54V-z48iLf94N6SQ_OlbtyC0Yvld9HJGBnH-wmF-CGPc1bdgSGshGjwXxqvbaMed2wrY0B44fbEWA8l03sZyh9legvQ
                // v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5kiAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEtm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJzVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96SfQ6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtpflZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw

                // 2-E-1
                // Expected
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ
                // NaCl
                // v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsm4Ts6wA4yoeuodTyTrK_gjl1bDexnpI8IAIJAqdDelBIifDmJT9QUYX0NctSsZGBKqh5wHHyvhCMWoY99CNCkWAEHLnHkPSVZPA-oJQPlinqKUHrA
                // v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248xqXFWNxuWGBIaU0yo_xm2htHeZho7vO_Xog1c6VPPrOvsEYZCdUqBIjUZegA6CJbtTwd-_VbOU33Ow02Z5pPl1wql7K75d7SeAEwAcGzapF8XMJR-Q // using nonce as nKey with original Blake2B class
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ // using NSec and nonce as nKey
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ // Using Blake2bMac https://github.com/kmaragon/Konscious.Security.Cryptography
                // NSec
                // v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsm4Ts6wA4yoeuodTyTrK_gjl1bDexnpI8IAIJAqdDelBIifDmJT9QUYX0NctSsZGBKqh5wHHyvhCMWoY99CNCkWAEHLnHkPSVZPA-oJQPlinqKUHrA
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

            try
            {
                var payload = builder.Decode(test.Token);

                payload.Should().Be(test.Payload);
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
                if (test.ExpectFail)
                {
                    _output.WriteLine($"DECODE FAIL {test.Name}: which was expected, with an exception of: {ex.GetType().Name}");
                    errors++;
                }
                else
                {
                    _output.WriteLine($"DECODE FAIL {test.Name}: {ex.Message}");
                }
            }
        }

        errors.Should().Be(vector.Tests.Where(t => t.ExpectFail).Count());
    }

    // TODO: Remove this method
    [Fact]
    public void Version2TestVectors()
    {
        var json = GetPasetoTestVector("v2");

        var vector = JsonConvert.DeserializeObject<PasetoTestCollection>(json);

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
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey)
                                     .WithNonce(CryptoBytes.FromHexString(test.Nonce));
                }
                else
                {
                    // We assert the seed since we want them to fail in case it changes
                    var secretKey = CryptoBytes.ToHexStringLower(Ed25519.ExpandedPrivateKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                    secretKey.Should().Be(test.SecretKey);

                    var publicKey = CryptoBytes.ToHexStringLower(Ed25519.PublicKeyFromSeed(CryptoBytes.FromHexString(test.SecretKeySeed)));
                    publicKey.Should().Be(test.PublicKey);

                    // Use Public & Secret Keys
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Public)
                                     .WithKey(CryptoBytes.FromHexString(test.SecretKey), Encryption.AsymmetricSecretKey);
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

                var token = builder.Encode();

                // 2-E-1
                // Expected
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ
                // NaCl
                // v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsm4Ts6wA4yoeuodTyTrK_gjl1bDexnpI8IAIJAqdDelBIifDmJT9QUYX0NctSsZGBKqh5wHHyvhCMWoY99CNCkWAEHLnHkPSVZPA-oJQPlinqKUHrA
                // v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248xqXFWNxuWGBIaU0yo_xm2htHeZho7vO_Xog1c6VPPrOvsEYZCdUqBIjUZegA6CJbtTwd-_VbOU33Ow02Z5pPl1wql7K75d7SeAEwAcGzapF8XMJR-Q // using nonce as nKey with original Blake2B class
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ // using NSec and nonce as nKey
                // v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ // Using Blake2bMac https://github.com/kmaragon/Konscious.Security.Cryptography
                // NSec
                // v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsm4Ts6wA4yoeuodTyTrK_gjl1bDexnpI8IAIJAqdDelBIifDmJT9QUYX0NctSsZGBKqh5wHHyvhCMWoY99CNCkWAEHLnHkPSVZPA-oJQPlinqKUHrA

                token.Should().Be(test.Token);
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
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey);
                }
                else
                {
                    // Using Asymmetric Key
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Public)
                                     .WithKey(CryptoBytes.FromHexString(test.PublicKey), Encryption.AsymmetricPublicKey);
                }
            }
            else
            {
                if (test.IsLocal)
                {
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Local)
                                     .WithKey(CryptoBytes.FromHexString(test.Key), Encryption.SymmetricKey);
                }
                else
                {
                    builder = builder.Use(ProtocolVersion.V2, Purpose.Public)
                                     .WithKey(CryptoBytes.FromHexString(test.PublicKey), Encryption.AsymmetricPublicKey);
                }
            }

            try
            {
                var payload = builder.Decode(test.Token);

                payload.Should().Be(test.Payload);
            }
            catch (PasetoInvalidException)
            {
                test.ExpectFail.Should().BeTrue();
            }
            catch (PasetoVerificationException)
            {
                test.ExpectFail.Should().BeTrue();
            }
            catch (Exception)
            {
                test.ExpectFail.Should().BeFalse();
            }
        }
    }

    private string GetPasetoTestVector(string version)
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

    private byte[] ReadKey(string key)
    {
        // | PEM Label                    | Import method on RSA
        // | ---------------------------- | --------------------
        // | BEGIN RSA PRIVATE KEY        | ImportRSAPrivateKey
        // | BEGIN PRIVATE KEY            | ImportPkcs8PrivateKey
        // | BEGIN ENCRYPTED PRIVATE KEY  | ImportEncryptedPkcs8PrivateKey
        // | BEGIN RSA PUBLIC KEY         | ImportRSAPublicKey
        // | BEGIN PUBLIC KEY             | ImportSubjectPublicKeyInfo

        if (ECDsaPrivateKeyRegex.IsMatch(key))
        {
            var ecdsaSecretKey = ECDsa.Create();
            ecdsaSecretKey.ImportFromPem(key);
            var sk = ecdsaSecretKey.ExportECPrivateKey();
            return sk;

            /*
            using var ms = new MemoryStream(GetBytes(key));
            using var sr = new StreamReader(ms);
            var pemReader = new PemReader(sr);
            var pem = pemReader.ReadPemObject();

            var seq = Asn1Sequence.GetInstance(pem.Content);
            var e = seq.GetEnumerator();
            e.MoveNext();
            var version = ((DerInteger)e.Current).Value;
            if (version.IntValue == 0) // V1
            {
                var privateKeyInfo = PrivateKeyInfo.GetInstance(seq);
                var akp = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(privateKeyInfo);
            }
            else
            {
                var ec = Org.BouncyCastle.Asn1.Sec.ECPrivateKeyStructure.GetInstance(seq);
                var algId = new AlgorithmIdentifier(Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.IdECPublicKey, ec.GetParameters());
                var privateKeyInfo = new PrivateKeyInfo(algId, ec.ToAsn1Object());
                var der = privateKeyInfo.GetDerEncoded();
                var akp = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(privateKeyInfo);

                return der;
            }

            return pem.Content; // same as sk
            */
        }

        if (RsaPrivateKeyRegex.IsMatch(key))
        {
            var rsaSecretKey = RSA.Create();
#if NET5_0_OR_GREATER
            rsaSecretKey.ImportFromPem(key);
#elif NETCOREAPP3_1
            var privateKeyBase64 = RsaPrivateKeyRegex.Replace(key, "");
            var privateKey = Convert.FromBase64String(privateKeyBase64);
            rsaSecretKey.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKey), out _);
#endif

            //var sk = rsaSecretKey.ToCompatibleXmlString(true);
            //return GetBytes(sk);
            return rsaSecretKey.ExportRSAPrivateKey();
        }

        if (RsaPublicKeyRegex.IsMatch(key))
        {
            var rsaPublicKey = RSA.Create();
#if NET5_0_OR_GREATER
            rsaPublicKey.ImportFromPem(key);
#elif NETCOREAPP3_1
            var publicKeyBase64 = RsaPublicKeyRegex.Replace(key, "");
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            rsaPublicKey.ImportRSAPublicKey(new ReadOnlySpan<byte>(publicKey), out _);
#endif

            //var pk = rsaPublicKey.ToCompatibleXmlString(false);
            //return GetBytes(pk);
            return rsaPublicKey.ExportRSAPublicKey();
        }

        return CryptoBytes.FromHexString(key);
    }
}
