using System;
using System.Linq;
using System.Security.Cryptography;
using Paseto;
using Paseto.Cryptography.Key;
using static Paseto.Utils.EncodingHelper;

internal static class PaserkHelpers
{
    private const int SYM_KEY_SIZE_IN_BYTES = 32;

    private const int V1_ASYM_MIN_PUBLIC_KEY_SIZE = 292;
    private const int V1_ASYM_MIN_PRIVATE_KEY_SIZE = 1180;

    private const int V2V4_ASYM_PUBLIC_KEY_SIZE = 32;
    private const int V2V4_ASYM_PRIVATE_KEY_SIZE = 64;

    private const int V3_ASYM_MIN_PRIVATE_KEY_SIZE = 48;

    internal static string SimpleEncode(string header, PaserkType type, PasetoKey pasetoKey)
    {
        var version = StringToVersion(pasetoKey.Protocol.Version);

        if (!Paserk.IsKeyCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        ValidateKeyLength(type, version, pasetoKey.Key.Length);

        return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
    }

    internal static PasetoKey SimpleDecode(PaserkType type, ProtocolVersion version, string encodedKey)
    {
        var key = FromBase64Url(encodedKey);
        var protocolVersion = Paserk.CreateProtocolVersion(version);

        ValidateKeyLength(type, version, key.Length);

        return type switch
        {
            PaserkType.Local => new PasetoSymmetricKey(key, protocolVersion),
            PaserkType.Public => new PasetoAsymmetricPublicKey(key, protocolVersion),
            PaserkType.Secret => new PasetoAsymmetricSecretKey(key, protocolVersion),

            _ => throw new PaserkInvalidException($"Error type {type} is not compatible with ${nameof(SimpleDecode)}"),
        };
    }

    internal static void ValidateKeyLength(PaserkType type, ProtocolVersion version, int length) => _ = (type, version, length) switch
    {
        (PaserkType.Local, _, not SYM_KEY_SIZE_IN_BYTES) => throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}."),

        (PaserkType.Public, ProtocolVersion.V1, < V1_ASYM_MIN_PUBLIC_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V1_ASYM_MIN_PUBLIC_KEY_SIZE}."),
        (PaserkType.Public, ProtocolVersion.V2 or ProtocolVersion.V4, not V2V4_ASYM_PUBLIC_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PUBLIC_KEY_SIZE}."),

        (PaserkType.Secret, ProtocolVersion.V1, < V1_ASYM_MIN_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V1_ASYM_MIN_PRIVATE_KEY_SIZE}."),
        (PaserkType.Secret, ProtocolVersion.V2 or ProtocolVersion.V4, not V2V4_ASYM_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be {V2V4_ASYM_PRIVATE_KEY_SIZE}."),
        (PaserkType.Secret, ProtocolVersion.V3, < V3_ASYM_MIN_PRIVATE_KEY_SIZE) => throw new ArgumentException($"The key length in bytes must be at least {V3_ASYM_MIN_PRIVATE_KEY_SIZE}."),
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