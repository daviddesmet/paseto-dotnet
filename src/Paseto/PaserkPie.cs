namespace Paseto;

using System;
using System.Security.Cryptography;

using NaCl.Core;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using Paseto.Cryptography;
using Paseto.Internal;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Implements the PASERK "pie" (Paseto Interoperable Encryption) key-wrapping protocol used by
/// the <c>local-wrap</c> and <c>secret-wrap</c> types.
/// <para>
/// Algorithm reference:
/// <see href="https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md">operations/Wrap/pie.md</see>.
/// v1/v3 use AES-256-CTR + HMAC-SHA384; v2/v4 use XChaCha20 + BLAKE2b.
/// </para>
/// </summary>
internal static class PaserkPie
{
    private const byte DOMAIN_ENCRYPTION = 0x80;
    private const byte DOMAIN_AUTHENTICATION = 0x81;

    private const int NONCE_SIZE = 32;

    // v2/v4 (XChaCha20 + BLAKE2b)
    private const int SYMK_SIZE = 32;   // Ek
    private const int XCHACHA_NONCE_SIZE = 24; // n2
    private const int BLAKE_TAG_SIZE = 32;

    // v1/v3 (AES-256-CTR + HMAC-SHA384)
    private const int AES_NONCE_SIZE = 16; // n2
    private const int HMAC_TAG_SIZE = 48;

    /// <summary>
    /// Wraps the plaintext key <paramref name="ptk"/> with the wrapping key <paramref name="wk"/>.
    /// </summary>
    /// <returns>The full PASERK string (header + base64url payload).</returns>
    internal static string Wrap(string header, ProtocolVersion version, byte[] wk, byte[] ptk)
    {
        var h = GetBytes(header);
        var n = Rng.GetBytes(NONCE_SIZE);

        return version switch
        {
            ProtocolVersion.V2 or ProtocolVersion.V4 => WrapBlake(header, h, wk, ptk, n),
            ProtocolVersion.V1 or ProtocolVersion.V3 => WrapHmac(header, h, wk, ptk, n),
            _ => throw new PaserkNotSupportedException($"The protocol version {version} is currently not supported."),
        };
    }

    /// <summary>
    /// Unwraps a PASERK "pie" payload (base64url of <c>tag || nonce || ciphertext</c>) back to the
    /// plaintext key.
    /// </summary>
    internal static byte[] Unwrap(string header, ProtocolVersion version, byte[] wk, string dataB64)
    {
        var data = FromBase64Url(dataB64);
        var h = GetBytes(header);

        return version switch
        {
            ProtocolVersion.V2 or ProtocolVersion.V4 => UnwrapBlake(h, wk, data),
            ProtocolVersion.V1 or ProtocolVersion.V3 => UnwrapHmac(h, wk, data),
            _ => throw new PaserkNotSupportedException($"The protocol version {version} is currently not supported."),
        };
    }

    private static string WrapBlake(string header, byte[] h, byte[] wk, byte[] ptk, byte[] n)
    {
        var x = new Blake2bMac(wk, (SYMK_SIZE + XCHACHA_NONCE_SIZE) * 8).ComputeHash(CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, n));
        var ek = x[..SYMK_SIZE];
        var n2 = x[SYMK_SIZE..];
        var ak = new Blake2bMac(wk, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, n));

        try
        {
            var c = new byte[ptk.Length];
            using var algo = new XChaCha20(ek, 0);
            algo.Encrypt(ptk, n2, c);

            var t = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, n, c));

            return $"{header}{ToBase64Url(CryptoBytes.Combine(t, n, c))}";
        }
        finally
        {
            CryptoBytes.Wipe(x);
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n2);
            CryptoBytes.Wipe(ak);
        }
    }

    private static byte[] UnwrapBlake(byte[] h, byte[] wk, byte[] data)
    {
        var t = data[..BLAKE_TAG_SIZE];
        var n = data[BLAKE_TAG_SIZE..(BLAKE_TAG_SIZE + NONCE_SIZE)];
        var c = data[(BLAKE_TAG_SIZE + NONCE_SIZE)..];

        var ak = new Blake2bMac(wk, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, n));
        var t2 = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, n, c));

        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new PaserkInvalidException("Invalid authentication tag.");

        var x = new Blake2bMac(wk, (SYMK_SIZE + XCHACHA_NONCE_SIZE) * 8).ComputeHash(CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, n));
        var ek = x[..SYMK_SIZE];
        var n2 = x[SYMK_SIZE..];

        try
        {
            var ptk = new byte[c.Length];
            using var algo = new XChaCha20(ek, 0);
            algo.Encrypt(c, n2, ptk);
            return ptk;
        }
        finally
        {
            CryptoBytes.Wipe(x);
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n2);
            CryptoBytes.Wipe(ak);
        }
    }

    private static string WrapHmac(string header, byte[] h, byte[] wk, byte[] ptk, byte[] n)
    {
        var (ek, n2) = DeriveHmacEk(wk, n);
        var ak = HmacSha384(wk, CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, n))[..SYMK_SIZE];

        try
        {
            var c = AesCtr(ek, n2, ptk);
            var t = HmacSha384(ak, CryptoBytes.Combine(h, n, c));

            return $"{header}{ToBase64Url(CryptoBytes.Combine(t, n, c))}";
        }
        finally
        {
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n2);
            CryptoBytes.Wipe(ak);
        }
    }

    private static byte[] UnwrapHmac(byte[] h, byte[] wk, byte[] data)
    {
        var t = data[..HMAC_TAG_SIZE];
        var n = data[HMAC_TAG_SIZE..(HMAC_TAG_SIZE + NONCE_SIZE)];
        var c = data[(HMAC_TAG_SIZE + NONCE_SIZE)..];

        var ak = HmacSha384(wk, CryptoBytes.Combine(new[] { DOMAIN_AUTHENTICATION }, n))[..SYMK_SIZE];
        var t2 = HmacSha384(ak, CryptoBytes.Combine(h, n, c));

        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new PaserkInvalidException("Invalid authentication tag.");

        var (ek, n2) = DeriveHmacEk(wk, n);

        try
        {
            return AesCtr(ek, n2, c);
        }
        finally
        {
            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(n2);
            CryptoBytes.Wipe(ak);
        }
    }

    private static (byte[] ek, byte[] n2) DeriveHmacEk(byte[] wk, byte[] n)
    {
        var x = HmacSha384(wk, CryptoBytes.Combine(new[] { DOMAIN_ENCRYPTION }, n));
        var ek = x[..SYMK_SIZE];
        var n2 = x[SYMK_SIZE..(SYMK_SIZE + AES_NONCE_SIZE)];
        CryptoBytes.Wipe(x);
        return (ek, n2);
    }

    private static byte[] HmacSha384(byte[] key, byte[] message)
    {
        using var hmac = new HMACSHA384(key);
        return hmac.ComputeHash(message);
    }

    private static byte[] AesCtr(byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), nonce));
        return cipher.DoFinal(input);
    }
}
