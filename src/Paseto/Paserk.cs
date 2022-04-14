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
    public static string Encode(IPasetoProtocolVersion proto, Purpose purpose, PaserkType type)
    {
        if (GetCompatibility(type) != purpose)
            throw new PasetoNotSupportedException($"The PASERK type is not compatible with the {purpose} purpose.");

        var header = $"k{proto.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Local:
                return $"{header}{ToBase64Url(proto.GenerateSymmetricKey().Key.Span)}";
            case PaserkType.Public:
                return $"{header}{ToBase64Url(proto.GenerateAsymmetricKeyPair().PublicKey.Key.Span)}";
            case PaserkType.Secret:
                return $"{header}{ToBase64Url(proto.GenerateAsymmetricKeyPair().SecretKey.Key.Span)}";
            default:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
        }
    }

    public static string Encode(ProtocolVersion version, Purpose purpose, PaserkType type, PasetoKey pasetoKey)
    {
        var proto = CreateProtocolVersion(version);

        if (!pasetoKey.IsValidFor(proto, purpose))
            throw new PasetoNotSupportedException($"The PASETO key is not compatible with the {purpose} purpose.");

        if (GetCompatibility(type) != purpose)
            throw new PasetoNotSupportedException($"The PASERK type is not compatible with the {purpose} purpose.");

        var header = $"k{proto.VersionNumber}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Local:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.Public:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.Secret:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            default:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
        }
    }

    public static string Encode(ProtocolVersion version, PaserkType type, PasetoSymmetricKey pasetoKey)
    {
        var header = $"k{(int)version}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Lid:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.Local:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.LocalWrap:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.LocalPassword:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.Seal:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            default:
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }
    }

    public static string Encode(ProtocolVersion version, PaserkType type, PasetoAsymmetricSecretKey pasetoKey)
    {
        var header = $"k{(int)version}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Sid:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.Secret:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            case PaserkType.SecretWrap:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.SecretPassword:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            default:
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }
    }

    public static string Encode(ProtocolVersion version, PaserkType type, PasetoAsymmetricPublicKey pasetoKey)
    {
        var header = $"k{(int)version}.{GetCompatibility(type).ToDescription()}.";

        switch (type)
        {
            case PaserkType.Pid:
                throw new PasetoNotSupportedException($"The PASERK type {type} is currently not supported.");
            case PaserkType.Public:
                return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
            default:
                throw new PasetoNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}.");
        }
    }

    public static PasetoKey Decode(string serializedKey)
    {
        throw new NotImplementedException();
    }

    private static IPasetoProtocolVersion CreateProtocolVersion(ProtocolVersion version)
    {
#pragma warning disable IDE0022 // Use expression body for methods
        return version switch
        {
            ProtocolVersion.V1 => new Version1(),
            ProtocolVersion.V2 => new Version2(),
            ProtocolVersion.V3 => new Version3(),
            ProtocolVersion.V4 => new Version4(),
            _ => throw new PasetoNotSupportedException($"The protocol version {version} is currently not supported."),
        };
#pragma warning restore IDE0022 // Use expression body for methods
    }

    private static Purpose GetCompatibility(PaserkType type) => type switch
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

    private static bool IsDataEncoded(PaserkType type) => type switch
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

    private static bool IsFooterSafe(PaserkType type) => type switch
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
