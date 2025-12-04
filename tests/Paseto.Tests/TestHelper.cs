namespace Paseto.Tests;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Paseto.Extensions;
using Xunit;

public static class TestHelper
{
    private static readonly Regex ECDsaPrivateKeyRegex = new(@"-----(BEGIN|END) EC PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private static readonly Regex RsaPrivateKeyRegex = new(@"-----(BEGIN|END) (RSA|OPENSSH|ENCRYPTED) PRIVATE KEY-----[\W]*", RegexOptions.Compiled);
    private static readonly Regex RsaPublicKeyRegex = new(@"-----(BEGIN|END) PUBLIC KEY-----[\W]*", RegexOptions.Compiled);

    public static byte[] FromHexString(string hexString)
    {
        if (hexString is null)
            return null;

        if (hexString.Length % 2 != 0)
            throw new FormatException("The hex string is invalid because it has an odd length");

        var result = new byte[hexString.Length / 2];
        for (var i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);

        return result;
    }

    // Explanation is similar to ToHexStringUpper
    // constant 55 -> 87 and -7 -> -39 to compensate for the offset 32 between lowercase and uppercase letters
    public static string ToHexStringLower(byte[] data)
    {
        if (data is null)
            return null;

        var c = new char[data.Length * 2];
        int b;
        for (var i = 0; i < data.Length; i++)
        {
            b = data[i] >> 4;
            c[i * 2] = (char)(87 + b + (((b - 10) >> 31) & -39));
            b = data[i] & 0xF;
            c[i * 2 + 1] = (char)(87 + b + (((b - 10) >> 31) & -39));
        }

        return new string(c);
    }

    public static byte[] ReadKey(string key)
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

        return FromHexString(key);
    }

    public static TheoryData<ProtocolVersion, Purpose> AllVersionsAndPurposesData()
    {
        var ret = new TheoryData<ProtocolVersion, Purpose>();

        foreach (var version in Enum.GetValues<ProtocolVersion>())
        foreach (var purpose in Enum.GetValues<Purpose>())
            ret.Add(version, purpose);

        return ret;
    }

    public static TheoryData<ProtocolVersion> AllVersionsData() =>  Enum.GetValues<ProtocolVersion>()
        .Aggregate(new TheoryData<ProtocolVersion>(), (x, y) =>
        {
            x.Add(y);
            return x;
        });

    public static TheoryData<string> VersionStringNameData() =>  Enum.GetValues<ProtocolVersion>()
        .Select(x => x.ToDescription())
        .Aggregate(new TheoryData<string>(), (x, y) =>
        {
            x.Add(y);
            return x;
        });
}