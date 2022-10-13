namespace Paseto.PaserkOperations;

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NaCl.Core;
using NaCl.Core.Internal;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Paseto.Cryptography;
using Paseto.Cryptography.Internal;
using Paseto.Cryptography.Internal.Argon2;

internal record struct Pbkdf2EncryptionValues(string Header, byte[] Salt, int Iterations, byte[] Nonce, byte[] Edk, byte[] Tag);
internal record struct Argon2idEncryptionValues(string Header, byte[] Salt, long MemoryBytes, int Iterations, int Parallelism, byte[] Nonce, byte[] Edk, byte[] Tag);

internal static class Pbkw
{
    // For version V1 or V3.
    public static byte[] Pbkdf2Decryption(string header, string password, byte[] salt, int iterations, byte[] nonce, byte[] edk, byte[] t)
    {
        var headerBytes = Encoding.UTF8.GetBytes(header);
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        // Derive the pre-key k from the password and salt. k = PBKDF2-SHA384(pw, s, i)
        // var k = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA384, 384);
        var k = Pbkdf2.Sha384(passwordBytes, salt, iterations)[..32];

        using var sha = SHA384.Create();
        var FF = new byte[] { 255 };
        var FE = new byte[] { 254 };

        // Derive the authentication key(Ak) from SHA-384(0xFE || k).
        var ak = sha.ComputeHash(CryptoBytes.Combine(FE, k));

        // Recalculate the authentication tag t2 over h, s, i, n, and edk.
        // t2 = HMAC-SHA-384(msg = h || s || int2bytes(i) || n || edk, key = Ak)
        using var hmac = new HMACSHA384(ak);

        var bigI = ByteIntegerConverter.Int32ToBigEndianBytes(iterations);

        var msg = CryptoBytes.Combine(headerBytes, salt, bigI, nonce, edk);
        var t2 = hmac.ComputeHash(msg);

        // Compare t with t2 using a constant-time string comparison function.
        // If it fails, abort.
        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new Exception("Paserk has invalid authentication tag.");

        // Derive the encryption key (Ek) from SHA-384(0xFF || k).
        var ek = sha.ComputeHash(CryptoBytes.Combine(FF, k))[..32];

        // Decrypt the encrypted key (edk) with Ek and n to obtain the plaintext key ptk.
        // ptk = AES-256-CTR(msg=edk, key=Ek, nonce=n)
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce));
        return cipher.DoFinal(edk);
    }

    // For version V1 or V3.
    public static Pbkdf2EncryptionValues Pbkdf2Encryption(string header, byte[] key, string password, int iterations)
    {
        var ptk = key;
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        // Generate a random 256-bit (32 byte) salt (s).
        var salt = new byte[32];
        RandomNumberGenerator.Fill(salt);

        // Derive the pre-key k from the password and salt. k = PBKDF2-SHA384(pw, s, i)
        var k = Pbkdf2.Sha384(passwordBytes, salt, iterations)[..32];

        using var sha = SHA384.Create();
        var FF = new byte[] { 255 };
        var FE = new byte[] { 254 };

        // Derive the encryption key (Ek) from SHA-384(0xFF || k).
        var ek = sha.ComputeHash(CryptoBytes.Combine(FF, k))[..32];

        // Derive the authentication key (Ak) from SHA-384(0xFE || k).
        var ak = sha.ComputeHash(CryptoBytes.Combine(FE, k));

        // Generate a random 128-bit nonce (n).
        var nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);

        // Encrypt the plaintext key ptk with Ek and n to obtain the encrypted data key edk.
        // edk = AES-256-CTR(msg=ptk, key=Ek, nonce=n)
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce));
        var edk = cipher.DoFinal(ptk);

        // Calculate the authentication tag t over h, s, i, n, and edk
        // t = HMAC-SHA-384(msg = h || s || int2bytes(i) || n || edk, key = Ak)
        using var hmac = new HMACSHA384(ak);
        var bigI = ByteIntegerConverter.Int32ToBigEndianBytes(iterations);
        var h = Encoding.UTF8.GetBytes(header);
        var msg = CryptoBytes.Combine(h, salt, bigI, nonce, edk).ToArray();
        var tag = hmac.ComputeHash(msg);

        return new Pbkdf2EncryptionValues(header, salt, iterations, nonce, edk, tag);
    }

    // For version V2 or V4.
    public static byte[] Argon2IdDecrypt(string header, string password, byte[] salt, long memoryCostBytes, int time, int parallelism, byte[] nonce, byte[] edk, ReadOnlySpan<byte> t)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var memoryKiBytes = MemorytoKiBytes(memoryCostBytes);

        // Derive the pre-key k from the password and salt. k = Argon2id(pw, s, mem, time, para)
        using var argon = new Argon2id(passwordBytes)
        {
            DegreeOfParallelism = parallelism,
            Iterations = time,
            MemorySize = memoryKiBytes,
            Salt = salt
        };
        var preKey = argon.GetBytes(32);

        // Derive the authentication key (Ak) from crypto_generichash(0xFE || k).
        var FF = new byte[] { 255 };
        var FE = new byte[] { 254 };

        var prependedFE = CryptoBytes.Combine(FE, preKey);

        var blake = new Blake2bDigest(32*8);
        blake.BlockUpdate(prependedFE, 0, prependedFE.Length);
        var ak = new byte[32];
        blake.DoFinal(ak, 0);

        // Recalculate the authentication tag t2 over h, s, mem, time, para, n, and edk.
        var gen = new Blake2bMac(32 * 8) { Key = ak };

        var headerBytes = Encoding.UTF8.GetBytes(header);
        var memBytes = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(memBytes, memoryCostBytes);
        var timeBytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(timeBytes, time);
        var paraBytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(paraBytes, parallelism);

        var msg = CryptoBytes.Combine(headerBytes, salt, memBytes, timeBytes, paraBytes, nonce, edk);
        gen.Initialize();
        var t2 = gen.ComputeHash(msg);

        // Compare t with t2 using a constant-time string comparison function. If it fails, abort.
        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new Exception("Paserk has invalid authentication tag.");

        // Derive the encryption key (Ek) from crypto_generichash(0xFF || k).
        var prependedFF = CryptoBytes.Combine(FF, preKey);
        blake.Reset();
        blake.BlockUpdate(prependedFF, 0, prependedFF.Length);
        var ek = new byte[32];
        blake.DoFinal(ek, 0);

        // Decrypt the encrypted key (edk) with Ek and n to obtain the plaintext key ptk.
        // ptk = XChaCha20(msg=edk, key=Ek, nonce=n)
        var ptk = new byte[edk.Length];
        var algo = new XChaCha20(ek, 0);
        algo.Encrypt(edk, nonce, ptk);

        return ptk;
    }

    // For version V2 or V4.
    public static Argon2idEncryptionValues Argon2IdEncrypt(string header, byte[] key, string password, int memoryCostKiBytes, int time, int parallelism)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        long memoryCostBytes = memoryCostKiBytes * 1024;

        // Generate a random 128-bit(16 byte) salt(s).
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        // Derive the pre-key k from the password and salt. k = Argon2id(pw, s, mem, time, para)
        using var argon = new Argon2id(passwordBytes)
        {
            DegreeOfParallelism = parallelism,
            Iterations = time,
            MemorySize = memoryCostKiBytes,
            Salt = salt
        };
        var preKey = argon.GetBytes(32);

        // Derive the encryption key(Ek) from crypto_generichash(0xFF || k).
        var FF = new byte[] { 255 };
        var FE = new byte[] { 254 };

        var prependedFF = CryptoBytes.Combine(FF, preKey);

        var blake = new Blake2bDigest(32*8);
        blake.BlockUpdate(prependedFF, 0, prependedFF.Length);
        var ek = new byte[32];
        blake.DoFinal(ek, 0);

        // Derive the authentication key(Ak) from crypto_generichash(0xFE || k).
        var prependedFE = CryptoBytes.Combine(FE, preKey);

        blake.Reset();
        blake.BlockUpdate(prependedFE, 0, prependedFE.Length);
        var ak = new byte[32];
        blake.DoFinal(ak, 0);

        // Generate a random 192-bit(24 byte) nonce(n).
        var nonce = new byte[24];
        RandomNumberGenerator.Fill(nonce);

        // Encrypt the plaintext key(ptk) with Ek and n to obtain the encrypted data key edk.
        // edk = XChaCha20(msg=ptk, key=Ek, nonce=n)
        var edk = new byte[key.Length];
        var algo = new XChaCha20(ek, 0);
        algo.Encrypt(key, nonce, edk);

        // Calculate the authentication tag t over h, s, mem, time, para, n, and edk.
        // t = crypto_generichash(
        //     msg = h || s || long2bytes(mem) || int2bytes(time) || int2bytes(para) || n || edk,
        //     key = Ak,
        //     length = 32 # 32 bytes, 256 bits
        // )
        var gen = new Blake2bMac(32 * 8) { Key = ak };

        var headerBytes = Encoding.UTF8.GetBytes(header);

        var memBytes = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(memBytes, memoryCostBytes);

        var timeBytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(timeBytes, time);

        var paraBytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(paraBytes, parallelism);

        var msg = CryptoBytes.Combine(headerBytes, salt, memBytes, timeBytes, paraBytes, nonce, edk);
        gen.Initialize();
        var t = gen.ComputeHash(msg);

        // Return h, s, mem, time, para, n, edk, t.
        return new Argon2idEncryptionValues(header, salt, memoryCostKiBytes, time, parallelism, nonce, edk, t);
    }

    private static int MemorytoKiBytes(long memoryCostBytes)
    {
        if (memoryCostBytes > (long)int.MaxValue * 1024)
        {
            throw new ArgumentException($"Argument {nameof(memoryCostBytes)} cannot exceed {(long)int.MaxValue * 1024}.");
        }

        return (int)(memoryCostBytes / 1024);
    }
}