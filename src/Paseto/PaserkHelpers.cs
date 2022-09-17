using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Paseto;
using Paseto.Cryptography.Key;
using static Paseto.Utils.EncodingHelper;

internal static class PaserkHelpers
{
    private const int SYM_KEY_SIZE_IN_BYTES = 32;

    private const int V2V4_ASYM_PUBLIC_KEY_SIZE = 32;
    private const int V2V4_ASYM_PRIVATE_KEY_SIZE = 64;
    private const int V3_ASYM_MIN_PRIVATE_KEY_SIZE = 48;

    internal static string SimpleEncode(string header, PaserkType type, PasetoKey pasetoKey)
    {
        if (pasetoKey.Protocol is not { Version: "v1" or "v2" or "v3" or "v4" })
            throw new PaserkNotSupportedException($"The PASERK version {pasetoKey.Protocol.Version} is not supported");
        if (!Paserk.IsKeyCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        var length = pasetoKey.Key.Length;
        return (type, pasetoKey.Protocol.Version, length) switch
        {
            (PaserkType.Local, _, SYM_KEY_SIZE_IN_BYTES) => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            (PaserkType.Local, _, _) => throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}."),

            (PaserkType.Public, "v2" or "v4", V2V4_ASYM_PUBLIC_KEY_SIZE) when length == V2V4_ASYM_PUBLIC_KEY_SIZE => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            (PaserkType.Public, "v2" or "v4", _) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PUBLIC_KEY_SIZE}."),
            (PaserkType.Public, _, _) => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",

            (PaserkType.Secret, "v2" or "v4", V2V4_ASYM_PRIVATE_KEY_SIZE) => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            (PaserkType.Secret, "v2" or "v4", _) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PRIVATE_KEY_SIZE}."),

            (PaserkType.Secret, "v3", >= V3_ASYM_MIN_PRIVATE_KEY_SIZE) => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            (PaserkType.Secret, "v3", _) => throw new ArgumentException($"The key length in bytes must be at least {V3_ASYM_MIN_PRIVATE_KEY_SIZE}."),

            (PaserkType.Secret, _, _) => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",

            _ => throw new Exception($"Unsupported operation {type}"),
        };
    }

    internal static PasetoKey SimpleDecode(PaserkType type, ProtocolVersion version, string encodedKey)
    {
        var key = FromBase64Url(encodedKey);
        var protocolVersion = Paserk.CreateProtocolVersion(version);

        return (type, key.Length) switch
        {
            (PaserkType.Local, SYM_KEY_SIZE_IN_BYTES) => new PasetoSymmetricKey(key, protocolVersion),
            (PaserkType.Local,_) => throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}."),

            (PaserkType.Secret, V2V4_ASYM_PRIVATE_KEY_SIZE)Length == V2V4_ASYM_PRIVATE_KEY_SIZE => new PasetoAsymmetricSecretKey(DecodePrivateKey(encodedKey), protocolVersion),
            PaserkType.Secret when key.Length == V2V4_ASYM_PRIVATE_KEY_SIZE => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PRIVATE_KEY_SIZE}."),

            PaserkType.Secret => new PasetoAsymmetricSecretKey(DecodePrivateKey(encodedKey), protocolVersion),
            PaserkType.Public => new PasetoAsymmetricPublicKey(DecodePublicKey(encodedKey), protocolVersion),
            _ => throw new PaserkInvalidException($"Error type {type} is not compatible with ${nameof(SimpleDecode)}"),
        };
    }


    private static readonly Regex ECDsaPrivateKeyRegex = new(@"-----(BEGIN|END) EC PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private static readonly Regex RsaPrivateKeyRegex = new(@"-----(BEGIN|END) (RSA|OPENSSH|ENCRYPTED) PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private static readonly Regex RsaPublicKeyRegex = new(@"-----(BEGIN|END) PUBLIC KEY-----[\W]*", RegexOptions.Compiled);

    internal static byte[] DecodePublicKey(string encodedKey)
    {
        if (RsaPublicKeyRegex.IsMatch(encodedKey))
        {
            var rsaPublicKey = RSA.Create();
#if NET5_0_OR_GREATER
            rsaPublicKey.ImportFromPem(encodedKey);
#elif NETCOREAPP3_1
            var publicKeyBase64 = RsaPublicKeyRegex.Replace(key, "");
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            rsaPublicKey.ImportRSAPublicKey(new ReadOnlySpan<byte>(publicKey), out _);
#endif

            //var pk = rsaPublicKey.ToCompatibleXmlString(false);
            //return GetBytes(pk);
            return rsaPublicKey.ExportRSAPublicKey();
        }

        return FromBase64Url(encodedKey);
    }

    internal static byte[] DecodePrivateKey(string encodedKey)
    {
        if (ECDsaPrivateKeyRegex.IsMatch(encodedKey))
        {
            var ecdsaSecretKey = ECDsa.Create();
            ecdsaSecretKey.ImportFromPem(encodedKey);
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

        if (RsaPrivateKeyRegex.IsMatch(encodedKey))
        {
            var rsaSecretKey = RSA.Create();
#if NET5_0_OR_GREATER
            rsaSecretKey.ImportFromPem(encodedKey);
#elif NETCOREAPP3_1
            var privateKeyBase64 = RsaPrivateKeyRegex.Replace(key, "");
            var privateKey = Convert.FromBase64String(privateKeyBase64);
            rsaSecretKey.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKey), out _);
#endif

            //var sk = rsaSecretKey.ToCompatibleXmlString(true);
            //return GetBytes(sk);
            return rsaSecretKey.ExportRSAPrivateKey();
        }

        return FromBase64Url(encodedKey);
    }
}