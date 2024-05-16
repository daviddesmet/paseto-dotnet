namespace Paseto;

using System;
using System.Text.RegularExpressions;
using Paseto.Cryptography.Key;
using Paseto.Extensions;

/// <summary>
/// PASERK (Platform-Agnostic Serialized Keys) extension.
/// </summary>
public static class Paserk
{
    // TODO Refactor Paserk and PaserkHelpers

    private const string PARSEK_HEADER_K = "k";
    private static readonly Regex HeaderRegex = new(@"^k[1-9]\.\w", RegexOptions.Compiled);

    /// <summary>
    /// Encodes a PASETO key into a PASERK string.
    /// </summary>
    /// <param name="pasetoKey">The PASETO key.</param>
    /// <param name="type">The PASERK type.</param>
    /// <returns>The encoded serialized key in PASERK format.</returns>
    /// <exception cref="PaserkNotSupportedException">The PASERK type is not compatible with the specified key.</exception>
    /// <exception cref="PaserkNotSupportedException">The specified PASERK type is currently not supported.</exception>
    public static string Encode(PasetoKey pasetoKey, PaserkType type)
    {
        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";

        return type switch
        {
            PaserkType.Local or PaserkType.Public or PaserkType.Secret => PaserkHelpers.SimpleEncode(header, type, pasetoKey),
            PaserkType.Lid or PaserkType.Sid or PaserkType.Pid => PaserkHelpers.IdEncode(header, Encode(pasetoKey, PaserkHelpers.Map(type)), type, pasetoKey),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported.")
        };
    }

    /// <summary>
    /// Decodes a PASERK string into a PASETO key.
    /// </summary>
    /// <param name="serializedKey"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="PaserkInvalidException">Serialized key is not valid.</exception>
    /// <exception cref="PaserkInvalidException">Serialized key has an undefined version.</exception>
    /// <exception cref="PaserkInvalidException">Serialized key has an unsupported version.</exception>
    /// <exception cref="PaserkInvalidException">Decode is not supported for the PASERK type.</exception>
    /// <exception cref="PaserkNotSupportedException">The specified PASERK type is currently not supported.</exception>
    public static PasetoKey Decode(string serializedKey)
    {
        if (string.IsNullOrWhiteSpace(serializedKey))
            throw new ArgumentNullException(nameof(serializedKey));

        if (!HeaderRegex.IsMatch(serializedKey))
            throw new PaserkInvalidException("Serialized key is not valid.");

        var parts = serializedKey.Split('.');
        if (parts.Length is < 3 or > 4)
            throw new PaserkInvalidException("Serialized key is not valid.");

        if (!int.TryParse(parts[0][1..], out var version))
            throw new PaserkInvalidException("Serialized key has an undefined version.");

        if (!Enum.IsDefined(typeof(ProtocolVersion), version))
            throw new PaserkInvalidException("Serialized key has an unsupported version.");

        var type = parts[1].FromDescription<PaserkType>();

        var encodedKey = parts.Length > 3 ? parts[3] : parts[2];

        return type switch
        {
            PaserkType.Local or PaserkType.Secret or PaserkType.Public => PaserkHelpers.SimpleDecode(type, (ProtocolVersion)version, encodedKey),
            PaserkType.Lid or PaserkType.Sid or PaserkType.Pid => throw new PaserkInvalidException($"Decode is not supported for type {type}. Id should be used to determine which key should be used."),
            // PaserkType.LocalWrap => throw new NotImplementedException(),
            // PaserkType.LocalPassword => throw new NotImplementedException(),
            // PaserkType.Seal => throw new NotImplementedException(),
            // PaserkType.SecretWrap => throw new NotImplementedException(),
            // PaserkType.SecretPassword => throw new NotImplementedException(),
            _ => throw new PaserkNotSupportedException($"The PASERK type {type} is currently not supported."),
        };
    }

    public static Purpose GetPurpose(PaserkType type) => type switch
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
}