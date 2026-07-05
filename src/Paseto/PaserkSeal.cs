namespace Paseto;

using System;
using System.Security.Cryptography;

using NaCl.Core;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

using Paseto.Cryptography;
using Paseto.Internal;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Implements the PASERK "seal" public-key encryption used by the <c>seal</c> type: a symmetric
/// (local) key is encrypted to a recipient's asymmetric public key so that only the holder of the
/// matching secret key can recover it.
/// <para>
/// Algorithm reference:
/// <see href="https://github.com/paseto-standard/paserk/blob/master/operations/PKE.md">operations/PKE.md</see>.
/// v3 uses P-384 ECDH + SHA-384 + AES-256-CTR + HMAC-SHA384; v4 uses X25519 + BLAKE2b + XChaCha20.
/// </para>
/// </summary>
internal static class PaserkSeal
{
    private const byte DOMAIN_ENCRYPTION = 0x01;
    private const byte DOMAIN_AUTHENTICATION = 0x02;

    // v4 (X25519 + BLAKE2b + XChaCha20)
    private const int X25519_KEY_SIZE = 32;
    private const int XCHACHA_NONCE_SIZE = 24;
    private const int BLAKE_TAG_SIZE = 32;
    private const int ED25519_SECRET_KEY_SIZE = 64; // seed(32) || public(32)

    // v3 (P-384 ECDH + SHA-384 + AES-256-CTR + HMAC-SHA384)
    private const int P384_SHARED_SECRET_SIZE = 48;
    private const int P384_PUBLIC_KEY_SIZE = 49; // compressed
    private const int AES_KEY_SIZE = 32;
    private const int AES_NONCE_SIZE = 16;
    private const int HMAC_TAG_SIZE = 48;

    /// <summary>
    /// Seals the plaintext (local) key <paramref name="ptk"/> to the recipient's public key.
    /// </summary>
    /// <returns>The full PASERK string (header + base64url payload).</returns>
    internal static string Seal(string header, ProtocolVersion version, byte[] recipientPublicKey, byte[] ptk) => version switch
    {
        ProtocolVersion.V4 => SealX25519(header, recipientPublicKey, ptk),
        ProtocolVersion.V3 => SealP384(header, recipientPublicKey, ptk),
        _ => throw new PaserkNotSupportedException($"The protocol version {version} does not support the seal operation."),
    };

    /// <summary>
    /// Unseals a PASERK "seal" payload back to the plaintext (local) key using the recipient's secret key.
    /// </summary>
    internal static byte[] Unseal(string header, ProtocolVersion version, byte[] recipientSecretKey, string dataB64) => version switch
    {
        ProtocolVersion.V4 => UnsealX25519(header, recipientSecretKey, FromBase64Url(dataB64)),
        ProtocolVersion.V3 => UnsealP384(header, recipientSecretKey, FromBase64Url(dataB64)),
        _ => throw new PaserkNotSupportedException($"The protocol version {version} does not support the seal operation."),
    };

    #region v4 (X25519)

    private static string SealX25519(string header, byte[] edPublicKey, byte[] ptk)
    {
        var h = GetBytes(header);
        var xpk = Ed25519PublicKeyToX25519(edPublicKey);

        // Ephemeral X25519 keypair.
        var esk = RandomNumberGenerator.GetBytes(X25519_KEY_SIZE);
        var epk = new byte[X25519_KEY_SIZE];
        X25519.ScalarMultBase(esk, 0, epk, 0);

        var xk = new byte[X25519_KEY_SIZE];
        X25519.ScalarMult(esk, 0, xpk, 0, xk, 0);
        if (IsAllZero(xk))
            throw new PaserkInvalidException("Invalid public key for seal.");

        var ek = Blake2b(CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, h, xk, epk, xpk), BLAKE_TAG_SIZE * 8);
        var ak = Blake2b(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, h, xk, epk, xpk), BLAKE_TAG_SIZE * 8);
        var n = Blake2b(CryptoBytes.Combine(epk, xpk), XCHACHA_NONCE_SIZE * 8);

        try
        {
            var edk = new byte[ptk.Length];
            using var algo = new XChaCha20(ek, 0);
            algo.Encrypt(ptk, n, edk);

            var t = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, epk, edk));

            return $"{header}{ToBase64Url(CryptoBytes.Combine(t, epk, edk))}";
        }
        finally
        {
            CryptoBytes.Wipe(esk);
            CryptoBytes.Wipe(xk);
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(ak);
            CryptoBytes.Wipe(n);
        }
    }

    private static byte[] UnsealX25519(string header, byte[] edSecretKey, byte[] data)
    {
        if (edSecretKey.Length != ED25519_SECRET_KEY_SIZE)
            throw new PaserkInvalidException($"The sealing secret key length in bytes must be {ED25519_SECRET_KEY_SIZE}.");

        var h = GetBytes(header);
        var t = data[..BLAKE_TAG_SIZE];
        var epk = data[BLAKE_TAG_SIZE..(BLAKE_TAG_SIZE + X25519_KEY_SIZE)];
        var edk = data[(BLAKE_TAG_SIZE + X25519_KEY_SIZE)..];

        // Convert the Ed25519 secret/public key to X25519.
        var seed = edSecretKey[..X25519_KEY_SIZE];
        var xsk = Ed25519SeedToX25519(seed);
        var xpk = Ed25519PublicKeyToX25519(edSecretKey[X25519_KEY_SIZE..]);

        var xk = new byte[X25519_KEY_SIZE];
        X25519.ScalarMult(xsk, 0, epk, 0, xk, 0);
        if (IsAllZero(xk))
            throw new PaserkInvalidException("Invalid ephemeral public key.");

        var ak = Blake2b(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, h, xk, epk, xpk), BLAKE_TAG_SIZE * 8);
        var t2 = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, epk, edk));

        if (!CryptoBytes.ConstantTimeEquals(t, t2))
        {
            CryptoBytes.Wipe(xsk);
            CryptoBytes.Wipe(xk);
            CryptoBytes.Wipe(ak);
            throw new PaserkInvalidException("Invalid authentication tag.");
        }

        var ek = Blake2b(CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, h, xk, epk, xpk), BLAKE_TAG_SIZE * 8);
        var n = Blake2b(CryptoBytes.Combine(epk, xpk), XCHACHA_NONCE_SIZE * 8);

        try
        {
            var ptk = new byte[edk.Length];
            using var algo = new XChaCha20(ek, 0);
            algo.Encrypt(edk, n, ptk); // XChaCha20 is a stream cipher: encrypt == decrypt.
            return ptk;
        }
        finally
        {
            CryptoBytes.Wipe(seed);
            CryptoBytes.Wipe(xsk);
            CryptoBytes.Wipe(xk);
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(ak);
            CryptoBytes.Wipe(n);
        }
    }

    #endregion

    #region v3 (P-384)

    private static string SealP384(string header, byte[] pkCompressed, byte[] ptk)
    {
        var h = GetBytes(header);
        var dom = P384Domain();

        // Ephemeral P-384 keypair.
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(dom, new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var ephPriv = (ECPrivateKeyParameters)kp.Private;
        var ephPk = ((ECPublicKeyParameters)kp.Public).Q.GetEncoded(compressed: true);

        var recipient = new ECPublicKeyParameters(dom.Curve.DecodePoint(pkCompressed), dom);
        var xk = P384Ecdh(ephPriv, recipient);

        var (ek, n) = DeriveP384EkAndNonce(h, xk, ephPk, pkCompressed);
        var ak = Sha384(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, h, xk, ephPk, pkCompressed));

        try
        {
            var edk = AesCtr(ek, n, ptk);
            var t = HmacSha384(ak, CryptoBytes.Combine(h, ephPk, edk));

            return $"{header}{ToBase64Url(CryptoBytes.Combine(t, ephPk, edk))}";
        }
        finally
        {
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n);
            CryptoBytes.Wipe(ak);
            CryptoBytes.Wipe(xk);
        }
    }

    private static byte[] UnsealP384(string header, byte[] skRaw, byte[] data)
    {
        var h = GetBytes(header);
        var t = data[..HMAC_TAG_SIZE];
        var epk = data[HMAC_TAG_SIZE..(HMAC_TAG_SIZE + P384_PUBLIC_KEY_SIZE)];
        var edk = data[(HMAC_TAG_SIZE + P384_PUBLIC_KEY_SIZE)..];

        var dom = P384Domain();
        var sealSk = new ECPrivateKeyParameters(new BigInteger(1, skRaw), dom);
        var ephPub = new ECPublicKeyParameters(dom.Curve.DecodePoint(epk), dom);

        var xk = P384Ecdh(sealSk, ephPub);
        var pkCompressed = dom.G.Multiply(sealSk.D).GetEncoded(compressed: true);

        var ak = Sha384(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, h, xk, epk, pkCompressed));
        var t2 = HmacSha384(ak, CryptoBytes.Combine(h, epk, edk));

        if (!CryptoBytes.ConstantTimeEquals(t, t2))
        {
            CryptoBytes.Wipe(ak);
            CryptoBytes.Wipe(xk);
            throw new PaserkInvalidException("Invalid authentication tag.");
        }

        var (ek, n) = DeriveP384EkAndNonce(h, xk, epk, pkCompressed);

        try
        {
            return AesCtr(ek, n, edk);
        }
        finally
        {
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n);
            CryptoBytes.Wipe(ak);
            CryptoBytes.Wipe(xk);
        }
    }

    private static (byte[] ek, byte[] n) DeriveP384EkAndNonce(byte[] h, byte[] xk, byte[] epk, byte[] pk)
    {
        var tmp = Sha384(CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, h, xk, epk, pk));
        var ek = tmp[..AES_KEY_SIZE];
        var n = tmp[AES_KEY_SIZE..(AES_KEY_SIZE + AES_NONCE_SIZE)];
        CryptoBytes.Wipe(tmp);
        return (ek, n);
    }

    private static ECDomainParameters P384Domain()
    {
        var x9 = NistNamedCurves.GetByName("P-384");
        return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
    }

    private static byte[] P384Ecdh(ECPrivateKeyParameters priv, ECPublicKeyParameters pub)
    {
        var agreement = new ECDHBasicAgreement();
        agreement.Init(priv);
        var z = agreement.CalculateAgreement(pub);
        return BigIntegers.AsUnsignedByteArray(P384_SHARED_SECRET_SIZE, z);
    }

    private static byte[] AesCtr(byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), nonce));
        return cipher.DoFinal(input);
    }

    private static byte[] Sha384(byte[] message)
    {
        using var sha = SHA384.Create();
        return sha.ComputeHash(message);
    }

    private static byte[] HmacSha384(byte[] key, byte[] message)
    {
        using var hmac = new HMACSHA384(key);
        return hmac.ComputeHash(message);
    }

    #endregion

    #region key conversion helpers

    private static byte[] Blake2b(byte[] message, int sizeBits)
    {
        var digest = new Blake2bDigest(sizeBits);
        digest.BlockUpdate(message, 0, message.Length);
        var output = new byte[sizeBits / 8];
        digest.DoFinal(output, 0);
        return output;
    }

    // Prime of Curve25519: 2^255 - 19.
    private static readonly BigInteger P25519 = BigInteger.Two.Pow(255).Subtract(BigInteger.ValueOf(19));

    /// <summary>
    /// Converts an Ed25519 public key to the birationally-equivalent X25519 public key
    /// (u = (1 + y) / (1 - y) mod p), matching libsodium's
    /// <c>crypto_sign_ed25519_pk_to_curve25519</c>.
    /// </summary>
    private static byte[] Ed25519PublicKeyToX25519(byte[] edPublicKey)
    {
        if (edPublicKey.Length != X25519_KEY_SIZE)
            throw new PaserkInvalidException($"The sealing public key length in bytes must be {X25519_KEY_SIZE}.");

        // Ed25519 encodes y little-endian with the sign of x in the high bit; clear it to recover y.
        var yLe = (byte[])edPublicKey.Clone();
        yLe[^1] &= 0x7F;
        var y = new BigInteger(1, Reverse(yLe)).Mod(P25519);

        var oneMinusY = BigInteger.One.Subtract(y).Mod(P25519);
        var onePlusY = BigInteger.One.Add(y).Mod(P25519);
        var u = onePlusY.Multiply(oneMinusY.ModInverse(P25519)).Mod(P25519);

        return ToLittleEndian(u, X25519_KEY_SIZE);
    }

    /// <summary>
    /// Derives the X25519 secret scalar from an Ed25519 seed, matching libsodium's
    /// <c>crypto_sign_ed25519_sk_to_curve25519</c> (SHA-512 of the seed, then clamped).
    /// </summary>
    private static byte[] Ed25519SeedToX25519(byte[] seed)
    {
        var h = SHA512.HashData(seed);
        var xsk = h[..X25519_KEY_SIZE];
        xsk[0] &= 248;
        xsk[31] &= 127;
        xsk[31] |= 64;
        CryptoBytes.Wipe(h);
        return xsk;
    }

    private static byte[] ToLittleEndian(BigInteger value, int size)
    {
        var be = BigIntegers.AsUnsignedByteArray(size, value);
        return Reverse(be);
    }

    private static byte[] Reverse(byte[] input)
    {
        var output = (byte[])input.Clone();
        Array.Reverse(output);
        return output;
    }

    private static bool IsAllZero(byte[] value)
    {
        var acc = 0;
        foreach (var b in value)
            acc |= b;
        return acc == 0;
    }

    #endregion
}
