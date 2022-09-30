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
///
// TODO Refactor Paserk and PaserkHelpers
public static class Paserk
{
    private const string PARSEK_HEADER_K = "k";
    private static readonly Regex HeaderRegex = new(@"^k[1-9]\.\w", RegexOptions.Compiled);

    // TODO Use more informative errors. Ie correct key/paserktype pair but invalid ProtocolVersion should throw an error saying what method overload should be used.

    /// <summary>
    /// Wraps a Paseto key using a unique Pkdf2 encryption key derived from a password.
    /// This method is intended for <see cref="PaserkType.LocalPassword"/> and <see cref="PaserkType.SecretPassword"/> for versions <see cref="ProtocolVersion.V1"/> and <see cref="ProtocolVersion.V3"/>.
    /// </summary>
    /// <param name="pasetoKey">PasetoKey of type <see cref="PasetoSymmetricKey"/> or <see cref="PasetoAsymmetricSecretKey"/>.</param>
    /// <param name="type">PaserkType of type <see cref="PaserkType.LocalPassword"/> or <see cref="PaserkType.SecretPassword"/>.</param>
    /// <param name="password">Password used to derive encryption key.</param>
    /// <param name="iterations">The number of internal iterations to perform for the derivation.</param>
    /// <returns>Password wrapped <see cref="PasetoKey"/>.</returns>
    /// <exception cref="PaserkNotSupportedException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static string Encode(PasetoKey pasetoKey, PaserkType type, string password, int iterations = 100_000)
    {
        var version = PaserkHelpers.StringToVersion(pasetoKey.Protocol.Version);
        if (version is not (ProtocolVersion.V1 or ProtocolVersion.V3))
            throw new PaserkNotSupportedException($"The PASERK version {version} is not compatible with this method overload. Use versions V2 or V4 instead.");

        if (type is not (PaserkType.LocalPassword or PaserkType.SecretPassword))
            throw new PaserkNotSupportedException($"The PASERK type {type} is not compatible with this method overload. Use LocalPassword or SecretPassword instead");

        if (!IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        if (string.IsNullOrEmpty(password))
            throw new ArgumentException($"Value {nameof(password)} cannot be null or empty");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";
        return type switch
        {
            PaserkType.LocalPassword or PaserkType.SecretPassword => PaserkHelpers.PwEncodeXChaCha(header, password, iterations, type, pasetoKey),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    /// <summary>
    /// Wraps a Paseto key using a unique Argon2id encryption key derived from a password.
    /// This method is intended for <see cref="PaserkType.LocalPassword"/> and <see cref="PaserkType.SecretPassword"/> for versions <see cref="ProtocolVersion.V2"/> and <see cref="ProtocolVersion.V4"/>.
    /// </summary>
    /// <param name="pasetoKey">PasetoKey of type <see cref="PasetoSymmetricKey"/> or <see cref="PasetoAsymmetricSecretKey"/>.</param>
    /// <param name="type">PaserkType of type <see cref="PaserkType.LocalPassword"/> or <see cref="PaserkType.SecretPassword"/>.</param>
    /// <param name="password">Password used to derive encryption key.</param>
    /// <param name="memoryCost">Amount of memory to use in bytes..</param>
    /// <param name="iterations">The number of iterations to apply to the password hash.</param>
    /// <param name="degreeOfParallelism">The number of lanes to use while processing the hash.</param>
    /// <returns>Password wrapped <see cref="PasetoKey"/>.</returns>
    /// <exception cref="PaserkNotSupportedException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static string Encode(PasetoKey pasetoKey, PaserkType type, string password, long memoryCost, int iterations, int degreeOfParallelism = 1)
    {
        var version = PaserkHelpers.StringToVersion(pasetoKey.Protocol.Version);
        if (version is not (ProtocolVersion.V2 or ProtocolVersion.V4))
            throw new PaserkNotSupportedException($"The PASERK version {version} is not compatible with this method overload. Use versions V2 or V4 instead.");

        if (type is not (PaserkType.LocalPassword or PaserkType.SecretPassword))
            throw new PaserkNotSupportedException($"The PASERK type {type} is not compatible with this method overload. Use LocalPassword or SecretPassword instead");

        if (!IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        if (string.IsNullOrEmpty(password))
            throw new ArgumentException($"Value {nameof(password)} cannot be null or empty");

        if (memoryCost > (long)int.MaxValue * 1024)
            throw new ArgumentException($"Argument {nameof(memoryCost)} cannot exceed {(long)int.MaxValue * 1024}.");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";
        return type switch
        {
            PaserkType.LocalPassword or PaserkType.SecretPassword => PaserkHelpers.PwEncodeArgon2(header, password, memoryCost, iterations, degreeOfParallelism, type, pasetoKey),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    /// <summary>
    /// Encodes a valid <see cref="PasetoKey"/> using a <see cref="PaserkType"/> operation.
    /// </summary>
    /// <param name="pasetoKey">Valid <see cref="PasetoKey"/>.</param>
    /// <param name="type"><see cref="PaserkType"/> sets the key wrapping operation. Note that certain operations may require additional arguments.</param>
    /// <returns>Encoded <see cref="PasetoKey"/>.</returns>
    /// <exception cref="PaserkNotSupportedException"></exception>
    public static string Encode(PasetoKey pasetoKey, PaserkType type)
    {
        if (!IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type is not compatible with the key {pasetoKey}.");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";

        return type switch
        {
            PaserkType.Local or PaserkType.Public or PaserkType.Secret => PaserkHelpers.SimpleEncode(header, type, pasetoKey),
            PaserkType.Lid or PaserkType.Sid or PaserkType.Pid => PaserkHelpers.IdEncode(header, type, pasetoKey),

            PaserkType.LocalPassword or PaserkType.SecretPassword => throw new PaserkNotSupportedException($"The PASERK type {type} requires a password to be provided."),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    // TODO implement key specific operations or remove?.
    public static string Encode(PasetoSymmetricKey pasetoKey, PaserkType type)
    {
        if (!IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK type {type} is not compatible with the a compatible with {nameof(pasetoKey)}.");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";

        return type switch
        {
            PaserkType.Local => LocalEncode(),
            PaserkType.Lid => throw new NotImplementedException(),
            PaserkType.LocalWrap => throw new NotImplementedException(),
            PaserkType.LocalPassword => throw new NotImplementedException(),
            PaserkType.Seal => throw new NotImplementedException(),
            _ => throw new PaserkNotSupportedException($"The PASETO key is not compatible with the PASERK type {type}."),
        };

        string LocalEncode()
        {
            if (pasetoKey.Key.Length < 32)
                throw new PaserkInvalidException("Symmetric keys must be 256-bit");

            return $"{header}{ToBase64Url(pasetoKey.Key.Span)}";
        }
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

    public static PasetoKey Decode(string serializedKey, string password = null)
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

        var encodedKey = parts.Length > 3 ? parts[3] : parts[2];

        return type switch
        {
            PaserkType.Local or PaserkType.Secret or PaserkType.Public => PaserkHelpers.SimpleDecode(type, (ProtocolVersion)version, encodedKey),

            PaserkType.Lid or PaserkType.Sid or PaserkType.Pid => throw new PaserkNotSupportedException($"Decode is not supported for type {type}. Id should be used to determine which key should be used."),

            PaserkType.LocalPassword or PaserkType.SecretPassword => PaserkHelpers.PwDecode(type, (ProtocolVersion)version, serializedKey, password),

            PaserkType.LocalWrap => throw new NotImplementedException(),
            PaserkType.SecretWrap => throw new NotImplementedException(),
            PaserkType.Seal => throw new NotImplementedException(),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported."),
        };
    }

    public static bool IsKeyTypeCompatible(PaserkType type, PasetoKey key) => key switch
    {
        PasetoSymmetricKey => type is PaserkType.Local or PaserkType.Lid or PaserkType.LocalPassword or PaserkType.LocalWrap,
        PasetoAsymmetricPublicKey => type is PaserkType.Public or PaserkType.Pid,
        PasetoAsymmetricSecretKey => type is PaserkType.Secret or PaserkType.Sid or PaserkType.SecretPassword or PaserkType.SecretWrap or PaserkType.Seal,
        _ => false,
    };

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