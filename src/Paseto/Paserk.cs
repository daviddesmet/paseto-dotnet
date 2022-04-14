namespace Paseto;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Paseto.Cryptography.Key;
using Paseto.Extensions;
using Paseto.Protocol;
using static Paseto.Utils.EncodingHelper;

public static class Paserk
{
    public static string Encode(PasetoKey pasetoKey, Purpose purpose, PaserkType type)
    {
        if (GetCompatibility(type) != purpose)
            throw new PasetoNotSupportedException($"The PASERK type is not compatible with the {purpose} purpose.");

        var header = $"k{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        return type switch
        {
            PaserkType.Local => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            PaserkType.Public => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            PaserkType.Secret => $"{header}{ToBase64Url(pasetoKey.Key.Span)}",
            _ => throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    public static string Encode(PasetoSymmetricKey pasetoKey, PaserkType type)
    {
        var header = $"k{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

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
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static string Encode(PasetoAsymmetricSecretKey pasetoKey, PaserkType type)
    {
        var header = $"k{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

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
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static string Encode(PasetoAsymmetricPublicKey pasetoKey, PaserkType type)
    {
        var header = $"k{pasetoKey.Protocol.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Pid:
                break;
            case PaserkType.Public:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            default:
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }

        throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
    }

    public static PasetoKey Decode(string serializedKey)
    {
        throw new NotImplementedException();
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
        _ => throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported."),
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
        _ => throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported."),
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
        _ => throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported."),
    };
}
