using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NaCl.Core.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Paseto.Cryptography;
using Paseto.Cryptography.Internal;

namespace Paseto.PaserkOperations;

public record struct Pbkdf2EncryptionValues(string Header, byte[] Salt, int Iterations, byte[] Nonce, byte[] Edk, byte[] Tag);

internal static class Pbkw
{
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
        var ak = sha.ComputeHash(FE.Concat(k).ToArray());

        // Recalculate the authentication tag t2 over h, s, i, n, and edk.
        // t2 = HMAC-SHA-384(msg = h || s || int2bytes(i) || n || edk, key = Ak)
        using var hmac = new HMACSHA384(ak);

        var bigI = ByteIntegerConverter.Int32ToBigEndianBytes(iterations);

        var msg = headerBytes.Concat(salt)
                             .Concat(bigI)
                             .Concat(nonce)
                             .Concat(edk)
                             .ToArray();
        var t2 = hmac.ComputeHash(msg);

        // Compare t with t2 using a constant-time string comparison function.
        // If it fails, abort.
        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new Exception("Paserk has invalid authentication tag.");

        // Derive the encryption key (Ek) from SHA-384(0xFF || k).
        var ek = sha.ComputeHash(FF.Concat(k).ToArray())[..32];

        // Decrypt the encrypted key (edk) with Ek and n to obtain the plaintext key ptk.
        // ptk = AES-256-CTR(msg=edk, key=Ek, nonce=n)
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce));
        return cipher.DoFinal(edk);
    }

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
        var ek = sha.ComputeHash(FF.Concat(k).ToArray())[..32];

        // Derive the authentication key (Ak) from SHA-384(0xFE || k).
        var ak = sha.ComputeHash(FE.Concat(k).ToArray());

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
        var msg = h.Concat(salt)
                   .Concat(bigI)
                   .Concat(nonce)
                   .Concat(edk)
                   .ToArray();
        var tag = hmac.ComputeHash(msg);

        return new Pbkdf2EncryptionValues(header, salt, iterations, nonce, edk, tag);
    }
}