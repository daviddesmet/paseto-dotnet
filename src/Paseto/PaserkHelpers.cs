using System;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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

        var ptk = System.Text.Encoding.UTF8.GetString(pasetoKey.Key.ToArray());

        if (version is ProtocolVersion.V1 or ProtocolVersion.V3)
        {
            var salt = new byte[32];
            RandomNumberGenerator.Fill(salt);

            var passwordBytes = Encoding.UTF8.GetBytes(password);

            //var pdb = new Pkcs5S2ParametersGenerator(new Sha384Digest());
            //pdb.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt, iterations);
            //var key = (KeyParameter)pdb.GenerateDerivedMacParameters(32);
            //var k = key.GetKey();

#if NET5_0
    throw new NotImplementedException();
#endif
#if NET6_0_OR_GREATER

            var k = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA384, 384);
            //k = k[..32];

            using var sha = SHA384.Create();
            var sfd = new byte[] { 255 };
            var asd = new byte[] { 254 };

            var ek = sha.ComputeHash(sfd.Concat(k).ToArray())[..32];
            var ak = sha.ComputeHash(asd.Concat(k).ToArray());

            var nonce = new byte[16];
            RandomNumberGenerator.Fill(nonce);

            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce));
            var edk = cipher.DoFinal(GetBytes(ptk));

            using var hmac = new HMACSHA384(ak);
            var i = BitConverter.GetBytes(iterations);
            var h = Encoding.UTF8.GetBytes(header);
            var msg = h.Concat(salt)
                       .Concat(i)
                       .Concat(nonce)
                       .Concat(edk)
                       .ToArray();
            var t = hmac.ComputeHash(msg);

            var output = salt.Concat(i).Concat(nonce).Concat(edk).Concat(t).ToArray();
            return $"{header}{ToBase64Url(output)}";
#endif
        }
        throw new NotImplementedException();

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