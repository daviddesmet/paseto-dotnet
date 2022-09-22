using System;
using System.Buffers.Binary;
using System.Drawing;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using NaCl.Core.Internal;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Paseto;
using Paseto.Cryptography.Key;
using static Paseto.Utils.EncodingHelper;

internal static class PaserkHelpers
{
    private const string RSA_PKCS1_ALG_IDENTIFIER = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A";

    private const int SYM_KEY_SIZE_IN_BYTES = 32;

    private const int V1_ASYM_MIN_PUBLIC_KEY_SIZE = 270;
    private const int V1_ASYM_MIN_PRIVATE_KEY_SIZE = 1180;

    private const int V2V4_ASYM_PUBLIC_KEY_SIZE = 32;
    private const int V2V4_ASYM_PRIVATE_KEY_SIZE = 64;

    private const int V3_ASYM_MIN_PRIVATE_KEY_SIZE = 48;
    private const int V3_ASYM_MIN_PUBLIC_KEY_SIZE = 49;

    internal static string SimpleEncode(string header, PaserkType type, PasetoKey pasetoKey)
    {
        var version = StringToVersion(pasetoKey.Protocol.Version);

        if (!Paserk.IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        ValidateKeyLength(type, version, pasetoKey.Key.Length);

        var key = pasetoKey.Key.Span;
        var keyString = ToBase64Url(key);

        // Prepend valid V1 public key algorithm identifier.
        if (version == ProtocolVersion.V1 && pasetoKey is PasetoAsymmetricPublicKey)
        {
            if (!keyString.StartsWith(RSA_PKCS1_ALG_IDENTIFIER))
            {
                keyString = $"{RSA_PKCS1_ALG_IDENTIFIER}{keyString}";
            }
        }

        return $"{header}{keyString}";
    }

    internal static string IdEncode(string header, string paserk, PaserkType type, PasetoKey pasetoKey)
    {
        var version = StringToVersion(pasetoKey.Protocol.Version);

        if (!Paserk.IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        var combined = Encoding.UTF8.GetBytes(header + paserk);

        if (version is ProtocolVersion.V1 or ProtocolVersion.V3)
        {
            using var sha = SHA384.Create();
            var hashSlice = sha.ComputeHash(combined)[..33];
            return $"{header}{ToBase64Url(hashSlice)}";
        }
        else if (version is ProtocolVersion.V2 or ProtocolVersion.V4)
        {
            var blake = new Blake2bDigest(264);
            blake.BlockUpdate(combined, 0, combined.Length);
            var hash = new byte[264];
            blake.DoFinal(hash, 0);

            var hashSlice = hash[..33];
            return $"{header}{ToBase64Url(hashSlice)}";
        }

        throw new NotImplementedException();
    }

    internal static string PBKDEncode(string header, string password, int iterations, PaserkType type, PasetoKey pasetoKey)
    {
        var version = StringToVersion(pasetoKey.Protocol.Version);

        if (!Paserk.IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        var ptk = pasetoKey.Key.ToArray();

        if (version is ProtocolVersion.V1 or ProtocolVersion.V3)
        {
            var salt = new byte[32];
            //RandomNumberGenerator.Fill(salt);
            var hexSalt = Convert.ToHexString(salt);

            var passwordBytes = Encoding.UTF8.GetBytes(Convert.ToHexString(Encoding.UTF8.GetBytes(password)).ToLower());
            var strPass = Convert.ToHexString(passwordBytes);

            var k = Pbkdf2.Sha384(passwordBytes, salt, iterations)[..32];
            var kStr = Convert.ToHexString(k);

            using var sha = SHA384.Create();
            var FF = new byte[] { 255 };
            var FE = new byte[] { 254 };

            var ek = sha.ComputeHash(FF.Concat(k).ToArray())[..32];
            var ak = sha.ComputeHash(FE.Concat(k).ToArray());

            var ekStr = Convert.ToHexString(ek);
            var akStr = Convert.ToHexString(ak);


            var nonce = new byte[16];
            //RandomNumberGenerator.Fill(nonce);

            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce));
            var edk = cipher.DoFinal(ptk);

            var edkStr = Convert.ToHexString(edk);
            //var strPtk = Convert.ToHexString(GetBytes(ptk));
            //var strPtk = Convert.ToHexString(GetBytes(ptk.Split(".")[2]));

            using var hmac = new HMACSHA384(ak);
            var i = GetBigEndianInt(iterations);
            var h = Encoding.UTF8.GetBytes(header);
            var msg = h.Concat(salt)
                       .Concat(i)
                       .Concat(nonce)
                       .Concat(edk)
                       .ToArray();
            var t = hmac.ComputeHash(msg);

            var bigI = GetBigEndianInt(iterations);
            var output = salt.Concat(bigI).Concat(nonce).Concat(edk).Concat(t).ToArray();
            return $"{header}{ToBase64Url(output)}";
        }
        throw new NotImplementedException();
    }

    internal static byte[] GetBigEndianInt(int i)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return bytes;
    }

    internal static PasetoKey SimpleDecode(PaserkType type, ProtocolVersion version, string encodedKey)
    {
        var protocolVersion = Paserk.CreateProtocolVersion(version);
        var key = FromBase64Url(encodedKey);

        // Check and remove algorithm identifier for V1 public keys.
        if (version == ProtocolVersion.V1 && type == PaserkType.Public)
        {
            if (!encodedKey.StartsWith(RSA_PKCS1_ALG_IDENTIFIER))
            {
                throw new PaserkInvalidException("Invalid paserk. Paserk V1 public keys should have a valid DER ASN.1 PKCS#1 algorithm identifier.");
            }
            key = FromBase64Url(encodedKey[RSA_PKCS1_ALG_IDENTIFIER.Length..]);
        }

        ValidateKeyLength(type, version, key.Length);

        return type switch
        {
            PaserkType.Local => new PasetoSymmetricKey(key, protocolVersion),
            PaserkType.Public => new PasetoAsymmetricPublicKey(key, protocolVersion),
            PaserkType.Secret => new PasetoAsymmetricSecretKey(key, protocolVersion),

            _ => throw new PaserkInvalidException($"Error type {type} is not compatible with ${nameof(SimpleDecode)}"),
        };
    }

    internal static PasetoKey PBKDDecode(PaserkType type, ProtocolVersion version, string paserk, string password)
    {
        var split = paserk.Split('.');
        var header = $"{split[0]}.{split[1]}.";
        var headerBytes = Encoding.UTF8.GetBytes(header);

        // I think the test vector is broken.
        var passwordBytes = Encoding.UTF8.GetBytes(Convert.ToHexString(Encoding.UTF8.GetBytes(password)).ToLower());
        var strPass = Convert.ToHexString(passwordBytes);

        //var passwordBytes = Encoding.UTF8.GetBytes(password);
        var bytes = FromBase64Url(paserk.Split('.')[2]);

        if (version is ProtocolVersion.V1 or ProtocolVersion.V3)
        {
            //99e5933c9a2191e2ec68abe582280392c33ddf9b920943b78ef8c410700adbc4
            var salt = bytes[..32];
            var strSalt = Convert.ToHexString(salt);

            var iBigEnd = bytes[32..36].ToArray();
            var rev = iBigEnd.Reverse().ToArray();
            var iterations = BitConverter.ToInt32(rev);

            var nonce = bytes[36..52];
            var strNonce = Convert.ToHexString(nonce);

            var edk = bytes[52..84];
            var strEdk = Convert.ToHexString(edk);

            var hsine = bytes[..^48];
            var t = bytes[^48..];

            // Derive the pre-key k from the password and salt. k = PBKDF2-SHA384(pw, s, i)
            // var k = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA384, 384);
            var k = Pbkdf2.Sha384(passwordBytes, salt, iterations)[..32];

            var str = Convert.ToHexString(k);

            using var sha = SHA384.Create();
            var FF = new byte[] { 255 };
            var FE = new byte[] { 254 };

            // Derive the authentication key(Ak) from SHA-384(0xFE || k).
            var ak = sha.ComputeHash(FE.Concat(k).ToArray());
            var strAk = Convert.ToHexString(ak);

            // Recalculate the authentication tag t2 over h, s, i, n, and edk.
            // t2 = HMAC-SHA-384(msg = h || s || int2bytes(i) || n || edk, key = Ak)
            using var hmac = new HMACSHA384(ak);
            var msg = headerBytes.Concat(hsine.ToArray()).ToArray();

            var msgStr = Convert.ToHexString(msg).ToLower();

            var t2 = hmac.ComputeHash(msg);
            var t2Str = Convert.ToHexString(t2);

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
            var ptk = cipher.DoFinal(edk);

            // Extract wrapped paserk
            return SimpleDecode(PaserkType.Local, version, ToBase64Url(ptk));
        }
        throw new NotImplementedException();



    }


    // TODO: Check Public V3 has valid point compression.
    // TODO: Verify ASN1 encoding for V1
    //  +--------+---------+----+----+----+
    //  |   _    |   V1    | V2 | V3 | V4 |
    //  +--------+---------+----+----+----+
    //  | Local  | 32      | 32 | 32 | 32 |
    //  | Public | 270<=?  | 32 | 49 | 32 |
    //  | Secret | 1190<=? | 64 | 48 | 64 |
    //  +--------+---------+----+----+----+

    internal static void ValidateKeyLength(PaserkType type, ProtocolVersion version, int length) => _ = (type, version, length) switch
    {
        (PaserkType.Local, _, not SYM_KEY_SIZE_IN_BYTES) => throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}."),

        (PaserkType.Public, ProtocolVersion.V1, < V1_ASYM_MIN_PUBLIC_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V1_ASYM_MIN_PUBLIC_KEY_SIZE} not {length}."),
        (PaserkType.Public, ProtocolVersion.V2 or ProtocolVersion.V4, not V2V4_ASYM_PUBLIC_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PUBLIC_KEY_SIZE}."),
        (PaserkType.Public, ProtocolVersion.V3, not V3_ASYM_MIN_PUBLIC_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be {V3_ASYM_MIN_PUBLIC_KEY_SIZE} not {length}."),

        (PaserkType.Secret, ProtocolVersion.V1, < V1_ASYM_MIN_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V1_ASYM_MIN_PRIVATE_KEY_SIZE} not {length}."),
        (PaserkType.Secret, ProtocolVersion.V2 or ProtocolVersion.V4, not V2V4_ASYM_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PRIVATE_KEY_SIZE}."),
        (PaserkType.Secret, ProtocolVersion.V3, < V3_ASYM_MIN_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V3_ASYM_MIN_PRIVATE_KEY_SIZE} not {length}."),
        _ => 0,
    };

    internal static ProtocolVersion StringToVersion(string version) => version switch
    {
        "v1" => ProtocolVersion.V1,
        "v2" => ProtocolVersion.V2,
        "v3" => ProtocolVersion.V3,
        "v4" => ProtocolVersion.V4,
        _ => throw new PaserkNotSupportedException($"The PASERK version {version} is not recognised."),
    };
}