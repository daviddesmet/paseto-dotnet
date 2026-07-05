namespace Paseto.Internal;

using System;
using System.Security.Cryptography;
#if NETFRAMEWORK
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
#endif

/// <summary>
/// PBKDF2 (RFC 2898) key derivation that works uniformly across target frameworks.
/// <para>
/// The static <see cref="Rfc2898DeriveBytes.Pbkdf2(byte[], byte[], int, HashAlgorithmName, int)"/>
/// overload is only available on .NET 6+. On .NET Framework the equivalent BouncyCastle primitive
/// (<c>Pkcs5S2ParametersGenerator</c>) is used, which produces identical output for the same inputs.
/// </para>
/// </summary>
internal static class Pbkdf2
{
    /// <summary>Derives <paramref name="outputLength"/> bytes using PBKDF2.</summary>
    internal static byte[] DeriveBytes(byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithmName, int outputLength)
    {
#if NETFRAMEWORK
        var generator = new Pkcs5S2ParametersGenerator(DigestFor(hashAlgorithmName));
        generator.Init(password, salt, iterations);
        var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(outputLength * 8);
        return keyParam.GetKey();
#else
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithmName, outputLength);
#endif
    }

#if NETFRAMEWORK
    private static IDigest DigestFor(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA384) return new Sha384Digest();
        if (name == HashAlgorithmName.SHA256) return new Sha256Digest();
        if (name == HashAlgorithmName.SHA512) return new Sha512Digest();
        throw new NotSupportedException($"Hash algorithm {name} is not supported for PBKDF2.");
    }
#endif
}
