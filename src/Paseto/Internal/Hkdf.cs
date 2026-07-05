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
/// HKDF (RFC 5869) key derivation that works uniformly across target frameworks.
/// <para>
/// The BCL <see cref="HKDF"/> type is only available on .NET 5+. On .NET Framework the equivalent
/// primitive from BouncyCastle (<c>HkdfBytesGenerator</c>) is used, which is byte-for-byte
/// interoperable with the BCL implementation for the same inputs.
/// </para>
/// </summary>
internal static class Hkdf
{
    /// <summary>
    /// Derives <paramref name="outputLength"/> bytes of key material from <paramref name="ikm"/>.
    /// A <c>null</c> <paramref name="salt"/> is treated as a zero-filled salt of the hash length,
    /// matching both RFC 5869 and the BCL/BouncyCastle behavior.
    /// </summary>
    internal static byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] ikm, int outputLength, byte[] info = null, byte[] salt = null)
    {
#if NETFRAMEWORK
        var hkdf = new HkdfBytesGenerator(DigestFor(hashAlgorithmName));
        hkdf.Init(new HkdfParameters(ikm, salt, info));
        var okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
#else
        return HKDF.DeriveKey(hashAlgorithmName, ikm, outputLength, salt, info);
#endif
    }

#if NETFRAMEWORK
    private static IDigest DigestFor(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA384) return new Sha384Digest();
        if (name == HashAlgorithmName.SHA256) return new Sha256Digest();
        if (name == HashAlgorithmName.SHA512) return new Sha512Digest();
        throw new NotSupportedException($"Hash algorithm {name} is not supported for HKDF.");
    }
#endif
}
