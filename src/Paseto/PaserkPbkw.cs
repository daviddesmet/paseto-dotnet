namespace Paseto;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

using NaCl.Core;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using Paseto.Cryptography;
using Paseto.Internal;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Implements the PASERK Password-Based Key Wrapping (PBKW) protocol used by the
/// <c>local-pw</c> and <c>secret-pw</c> types.
/// <para>
/// Algorithm reference:
/// <see href="https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md">operations/PBKW.md</see>.
/// v1/v3 use PBKDF2-SHA384 + AES-256-CTR; v2/v4 use Argon2id + XChaCha20.
/// </para>
/// </summary>
internal static class PaserkPbkw
{
    private const byte DOMAIN_ENCRYPTION = 0xFF;
    private const byte DOMAIN_AUTHENTICATION = 0xFE;

    private const int PREKEY_SIZE = 32;

    // v2/v4 (Argon2id + XChaCha20)
    private const int ARGON_SALT_SIZE = 16;
    private const int XCHACHA_NONCE_SIZE = 24;
    private const int BLAKE_TAG_SIZE = 32;

    // v1/v3 (PBKDF2-SHA384 + AES-256-CTR)
    private const int PBKDF2_SALT_SIZE = 32;
    private const int AES_NONCE_SIZE = 16;
    private const int HMAC_TAG_SIZE = 48;

    internal static string Encrypt(string header, ProtocolVersion version, byte[] password, PbkwOptions options, byte[] ptk)
    {
        options ??= new PbkwOptions();

        return version switch
        {
            ProtocolVersion.V2 or ProtocolVersion.V4 => EncryptArgon(header, password, options, ptk),
            ProtocolVersion.V1 or ProtocolVersion.V3 => EncryptPbkdf2(header, password, options, ptk),
            _ => throw new PaserkNotSupportedException($"The protocol version {version} is currently not supported."),
        };
    }

    internal static byte[] Decrypt(string header, ProtocolVersion version, byte[] password, string dataB64)
    {
        var data = FromBase64Url(dataB64);
        var h = GetBytes(header);

        return version switch
        {
            ProtocolVersion.V2 or ProtocolVersion.V4 => DecryptArgon(h, password, data),
            ProtocolVersion.V1 or ProtocolVersion.V3 => DecryptPbkdf2(h, password, data),
            _ => throw new PaserkNotSupportedException($"The protocol version {version} is currently not supported."),
        };
    }

    // ---- v2/v4 : Argon2id + XChaCha20 ----

    private static string EncryptArgon(string header, byte[] password, PbkwOptions options, byte[] ptk)
    {
        var h = GetBytes(header);
        var s = RandomNumberGenerator.GetBytes(ARGON_SALT_SIZE);
        var n = RandomNumberGenerator.GetBytes(XCHACHA_NONCE_SIZE);

        var k = Argon2id(password, s, options.MemoryLimitBytes, options.OpsLimit, options.Parallelism);
        try
        {
            var ek = Blake2b(DOMAIN_ENCRYPTION, k);
            var ak = Blake2b(DOMAIN_AUTHENTICATION, k);

            var edk = new byte[ptk.Length];
            using (var algo = new XChaCha20(ek, 0))
                algo.Encrypt(ptk, n, edk);

            // body = s || u64be(memlimit) || u32be(opslimit) || u32be(parallelism) || n || edk
            var parameters = new byte[8 + 4 + 4];
            BinaryPrimitives.WriteUInt64BigEndian(parameters.AsSpan(0, 8), (ulong)options.MemoryLimitBytes);
            BinaryPrimitives.WriteUInt32BigEndian(parameters.AsSpan(8, 4), (uint)options.OpsLimit);
            BinaryPrimitives.WriteUInt32BigEndian(parameters.AsSpan(12, 4), (uint)options.Parallelism);

            var body = CryptoBytes.Combine(s, parameters, n, edk);
            var t = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, body));

            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(ak);

            return $"{header}{ToBase64Url(CryptoBytes.Combine(body, t))}";
        }
        finally
        {
            CryptoBytes.Wipe(k);
        }
    }

    private static byte[] DecryptArgon(byte[] h, byte[] password, byte[] data)
    {
        var body = data[..^BLAKE_TAG_SIZE];
        var t = data[^BLAKE_TAG_SIZE..];

        var s = body[..ARGON_SALT_SIZE];
        var mem = (long)BinaryPrimitives.ReadUInt64BigEndian(body.AsSpan(ARGON_SALT_SIZE, 8));
        var ops = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(ARGON_SALT_SIZE + 8, 4));
        var para = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(ARGON_SALT_SIZE + 12, 4));
        var nOffset = ARGON_SALT_SIZE + 16;
        var n = body[nOffset..(nOffset + XCHACHA_NONCE_SIZE)];
        var edk = body[(nOffset + XCHACHA_NONCE_SIZE)..];

        var k = Argon2id(password, s, mem, ops, para);
        try
        {
            var ak = Blake2b(DOMAIN_AUTHENTICATION, k);
            var t2 = new Blake2bMac(ak, BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(h, body));
            CryptoBytes.Wipe(ak);

            if (!CryptoBytes.ConstantTimeEquals(t, t2))
                throw new PaserkInvalidException("Invalid authentication tag.");

            var ek = Blake2b(DOMAIN_ENCRYPTION, k);
            var ptk = new byte[edk.Length];
            using (var algo = new XChaCha20(ek, 0))
                algo.Encrypt(edk, n, ptk);
            CryptoBytes.Wipe(ek);

            return ptk;
        }
        finally
        {
            CryptoBytes.Wipe(k);
        }
    }

    // ---- v1/v3 : PBKDF2-SHA384 + AES-256-CTR ----

    private static string EncryptPbkdf2(string header, byte[] password, PbkwOptions options, byte[] ptk)
    {
        var h = GetBytes(header);
        var s = RandomNumberGenerator.GetBytes(PBKDF2_SALT_SIZE);
        var n = RandomNumberGenerator.GetBytes(AES_NONCE_SIZE);
        var i = options.Iterations;

        var k = Rfc2898DeriveBytes.Pbkdf2(password, s, i, HashAlgorithmName.SHA384, PREKEY_SIZE);
        try
        {
            var ek = Sha384(DOMAIN_ENCRYPTION, k)[..32];
            var ak = Sha384(DOMAIN_AUTHENTICATION, k);

            var edk = AesCtr(ek, n, ptk);

            var iterations = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(iterations, (uint)i);

            var body = CryptoBytes.Combine(s, iterations, n, edk);
            byte[] t;
            using (var hmac = new HMACSHA384(ak))
                t = hmac.ComputeHash(CryptoBytes.Combine(h, body));

            CryptoBytes.Wipe(ek);
            CryptoBytes.Wipe(ak);

            return $"{header}{ToBase64Url(CryptoBytes.Combine(body, t))}";
        }
        finally
        {
            CryptoBytes.Wipe(k);
        }
    }

    private static byte[] DecryptPbkdf2(byte[] h, byte[] password, byte[] data)
    {
        var body = data[..^HMAC_TAG_SIZE];
        var t = data[^HMAC_TAG_SIZE..];

        var s = body[..PBKDF2_SALT_SIZE];
        var i = (int)BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(PBKDF2_SALT_SIZE, 4));
        var nOffset = PBKDF2_SALT_SIZE + 4;
        var n = body[nOffset..(nOffset + AES_NONCE_SIZE)];
        var edk = body[(nOffset + AES_NONCE_SIZE)..];

        var k = Rfc2898DeriveBytes.Pbkdf2(password, s, i, HashAlgorithmName.SHA384, PREKEY_SIZE);
        try
        {
            var ak = Sha384(DOMAIN_AUTHENTICATION, k);
            byte[] t2;
            using (var hmac = new HMACSHA384(ak))
                t2 = hmac.ComputeHash(CryptoBytes.Combine(h, body));
            CryptoBytes.Wipe(ak);

            if (!CryptoBytes.ConstantTimeEquals(t, t2))
                throw new PaserkInvalidException("Invalid authentication tag.");

            var ek = Sha384(DOMAIN_ENCRYPTION, k)[..32];
            var ptk = AesCtr(ek, n, edk);
            CryptoBytes.Wipe(ek);

            return ptk;
        }
        finally
        {
            CryptoBytes.Wipe(k);
        }
    }

    // ---- primitives ----

    private static byte[] Argon2id(byte[] password, byte[] salt, long memoryLimitBytes, int opsLimit, int parallelism)
    {
        var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithSalt(salt)
            .WithIterations(opsLimit)
            .WithMemoryAsKB((int)(memoryLimitBytes / 1024))
            .WithParallelism(parallelism);

        var generator = new Argon2BytesGenerator();
        generator.Init(builder.Build());

        var output = new byte[PREKEY_SIZE];
        generator.GenerateBytes(password, output);
        return output;
    }

    private static byte[] Blake2b(byte domainSeparator, byte[] prekey)
        => new Blake2bMac(BLAKE_TAG_SIZE * 8).ComputeHash(CryptoBytes.Combine(new[] { domainSeparator }, prekey));

    private static byte[] Sha384(byte domainSeparator, byte[] prekey)
    {
        using var sha = SHA384.Create();
        return sha.ComputeHash(CryptoBytes.Combine(new[] { domainSeparator }, prekey));
    }

    private static byte[] AesCtr(byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), nonce));
        return cipher.DoFinal(input);
    }
}
