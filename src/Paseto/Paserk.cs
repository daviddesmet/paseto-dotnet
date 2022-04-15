namespace Paseto;

using System;
using System.Text.RegularExpressions;

using Paseto.Cryptography.Key;
using Paseto.Extensions;
using Paseto.Protocol;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// PASERK (Platform-Agnostic Serialized Keys) extension.
/// </summary>
public static class Paserk
{
    private const string PARSEK_HEADER_K = "k";
    private static readonly Regex HeaderRegex = new(@"^k[1-9]\.\w", RegexOptions.Compiled);

    public static string Encode(PasetoKey pasetoKey, Purpose purpose, PaserkType type)
    {
        if (GetCompatibility(type) != purpose)
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the {purpose} purpose.");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        return type switch
        {
            PaserkType.Local => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            PaserkType.Public => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            PaserkType.Secret => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    public static string Encode(PasetoSymmetricKey pasetoKey, PaserkType type)
    {
        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Lid:
                break;
            case PaserkType.Local:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.LocalWrap:
                break;
            case PaserkType.LocalPassword:
                break;
            case PaserkType.Seal:
                break;
            default:
                throw new PaserkNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static string Encode(PasetoAsymmetricSecretKey pasetoKey, PaserkType type)
    {
        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Sid:
                break;
            case PaserkType.Secret:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.SecretWrap:
                break;
            case PaserkType.SecretPassword:
                break;
            default:
                throw new PaserkNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static string Encode(PasetoAsymmetricPublicKey pasetoKey, PaserkType type)
    {
        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Pid:
                break;
            case PaserkType.Public:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            default:
                throw new PaserkNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static PasetoKey Decode(string serializedKey)
    {
        if (string.IsNullOrWhiteSpace(serializedKey))
            throw new ArgumentNullException(nameof(serializedKey));

        if (!HeaderRegex.IsMatch(serializedKey))
            throw new PaserkInvalidException("Serialized key is not valid");

        var parts = serializedKey.Split('.');
        if (parts.Length < 3 || parts.Length > 4)
            throw new PaserkInvalidException("Serialized key is not valid");

        if (!int.TryParse(parts[0][1..], out var version))
            throw new PaserkInvalidException("Serialized key has an undefined version");

        if (!Enum.IsDefined(typeof(ProtocolVersion), version))
            throw new PaserkInvalidException("Serialized key has an unsupported version");

        var type = parts[1].FromDescription<PaserkType>();
        //var purpose = GetCompatibility(type);

        var encodedKey = parts.Length > 3 ? parts[3] : parts[2];
        var key = FromBase64Url(encodedKey);

        switch (type)
        {
            case PaserkType.Lid:
                break;
            case PaserkType.Local:
                return new PasetoSymmetricKey(key, CreateProtocolVersion((ProtocolVersion)version));
            case PaserkType.LocalWrap:
                break;
            case PaserkType.LocalPassword:
                break;
            case PaserkType.Seal:
                break;
            case PaserkType.Sid:
                break;
            case PaserkType.Secret:
                return new PasetoAsymmetricSecretKey(key, CreateProtocolVersion((ProtocolVersion)version));
            case PaserkType.SecretWrap:
                break;
            case PaserkType.SecretPassword:
                break;
            case PaserkType.Pid:
                break;
            case PaserkType.Public:
                return new PasetoAsymmetricPublicKey(key, CreateProtocolVersion((ProtocolVersion)version));
            default:
                throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
        }

        throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static Purpose GetCompatibility(PaserkType type) => type switch
    {
        PaserkType.Lid => Purpose.Local,
        PaserkType.Local => Purpose.Local,
        PaserkType.LocalWrap => Purpose.Local,
        PaserkType.LocalPassword => Purpose.Local,
        PaserkType.Seal => Purpose.Local,
        PaserkType.Sid => Purpose.Public,
        PaserkType.Secret => Purpose.Public,
        PaserkType.SecretWrap => Purpose.Public,
        PaserkType.SecretPassword => Purpose.Public,
        PaserkType.Pid => Purpose.Public,
        PaserkType.Public => Purpose.Public,
        _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported."),
    };

    public static bool IsDataEncoded(PaserkType type) => type switch
    {
        PaserkType.Lid => true,
        PaserkType.Local => true,
        PaserkType.LocalWrap => false,
        PaserkType.LocalPassword => true,
        PaserkType.Seal => true,
        PaserkType.Sid => true,
        PaserkType.Secret => true,
        PaserkType.SecretWrap => false,
        PaserkType.SecretPassword => true,
        PaserkType.Pid => true,
        PaserkType.Public => true,
        _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported."),
    };

    public static bool IsFooterSafe(PaserkType type) => type switch
    {
        PaserkType.Lid => true,
        PaserkType.Local => false,
        PaserkType.LocalWrap => true,
        PaserkType.LocalPassword => false,
        PaserkType.Seal => true,
        PaserkType.Sid => true,
        PaserkType.Secret => false,
        PaserkType.SecretWrap => true,
        PaserkType.SecretPassword => false,
        PaserkType.Pid => true,
        PaserkType.Public => false,
        _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported."),
    };

    internal static IPasetoProtocolVersion CreateProtocolVersion(ProtocolVersion version)
    {
#pragma warning disable IDE0022 // Use expression body for methods
        return version switch
        {
            ProtocolVersion.V1 => new Version1(),
            ProtocolVersion.V2 => new Version2(),
            ProtocolVersion.V3 => new Version3(),
            ProtocolVersion.V4 => new Version4(),
            _ => throw new PaserkNotSupportedException($"The protocol version {version} is currently not supported."),
        };
#pragma warning restore IDE0022 // Use expression body for methods
    }
}
