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

    /// <summary>
    /// Wraps a PASETO key with a symmetric wrapping key using the PASERK "pie" protocol
    /// (<see cref="PaserkType.LocalWrap"/> or <see cref="PaserkType.SecretWrap"/>).
    /// </summary>
    /// <param name="pasetoKey">The key to wrap.</param>
    /// <param name="type">The PASERK type (<c>local-wrap</c> or <c>secret-wrap</c>).</param>
    /// <param name="wrappingKey">The symmetric key used to wrap <paramref name="pasetoKey"/>.</param>
    /// <returns>The encoded serialized key in PASERK format.</returns>
    public static string Encode(PasetoKey pasetoKey, PaserkType type, PasetoSymmetricKey wrappingKey)
    {
        ArgumentNullException.ThrowIfNull(pasetoKey);
        ArgumentNullException.ThrowIfNull(wrappingKey);

        if (type is not (PaserkType.LocalWrap or PaserkType.SecretWrap))
            throw new PaserkNotSupportedException($"The PASERK type {type} does not support key wrapping.");

        if (!PaserkHelpers.IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK {type} is not compatible with the PASETO key.");

        var version = PaserkHelpers.GetProtocolVersion(pasetoKey);
        if (PaserkHelpers.GetProtocolVersion(wrappingKey) != version)
            throw new PaserkNotSupportedException("The wrapping key must use the same protocol version as the key being wrapped.");

        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.pie.";
        return PaserkPie.Wrap(header, version, wrappingKey.Key.ToArray(), pasetoKey.Key.ToArray());
    }

    /// <summary>
    /// Unwraps a PASERK "pie" serialized key (<c>local-wrap</c> / <c>secret-wrap</c>) using the
    /// symmetric wrapping key.
    /// </summary>
    /// <param name="serializedKey">The PASERK string.</param>
    /// <param name="wrappingKey">The symmetric key used to unwrap the serialized key.</param>
    public static PasetoKey Decode(string serializedKey, PasetoSymmetricKey wrappingKey)
    {
        ArgumentNullException.ThrowIfNull(wrappingKey);

        var (type, version, header, encodedKey) = ParseHeader(serializedKey);

        if (type is not (PaserkType.LocalWrap or PaserkType.SecretWrap))
            throw new PaserkNotSupportedException($"The PASERK type {type} does not support key unwrapping.");

        if (PaserkHelpers.GetProtocolVersion(wrappingKey) != version)
            throw new PaserkNotSupportedException("The wrapping key must use the same protocol version as the serialized key.");

        var ptk = PaserkPie.Unwrap(header, version, wrappingKey.Key.ToArray(), encodedKey);
        return BuildKey(type, version, ptk);
    }

    /// <summary>
    /// Wraps a PASETO key with a password using the PASERK PBKW protocol
    /// (<see cref="PaserkType.LocalPassword"/> or <see cref="PaserkType.SecretPassword"/>).
    /// </summary>
    /// <param name="pasetoKey">The key to wrap.</param>
    /// <param name="type">The PASERK type (<c>local-pw</c> or <c>secret-pw</c>).</param>
    /// <param name="password">The password used to derive the wrapping key.</param>
    /// <param name="options">The PBKW parameters. When <c>null</c>, sensible defaults are used.</param>
    /// <returns>The encoded serialized key in PASERK format.</returns>
    public static string Encode(PasetoKey pasetoKey, PaserkType type, ReadOnlySpan<byte> password, PbkwOptions options = null)
    {
        ArgumentNullException.ThrowIfNull(pasetoKey);

        if (type is not (PaserkType.LocalPassword or PaserkType.SecretPassword))
            throw new PaserkNotSupportedException($"The PASERK type {type} does not support password-based wrapping.");

        if (!PaserkHelpers.IsKeyTypeCompatible(type, pasetoKey))
            throw new PaserkNotSupportedException($"The PASERK {type} is not compatible with the PASETO key.");

        var version = PaserkHelpers.GetProtocolVersion(pasetoKey);
        var header = $"{PARSEK_HEADER_K}{pasetoKey.Protocol.VersionNumber}.{type.ToDescription()}.";
        return PaserkPbkw.Encrypt(header, version, password.ToArray(), options, pasetoKey.Key.ToArray());
    }

    /// <summary>
    /// Unwraps a PASERK PBKW serialized key (<c>local-pw</c> / <c>secret-pw</c>) using the password.
    /// </summary>
    /// <param name="serializedKey">The PASERK string.</param>
    /// <param name="password">The password used to derive the wrapping key.</param>
    public static PasetoKey Decode(string serializedKey, ReadOnlySpan<byte> password)
    {
        var (type, version, header, encodedKey) = ParseHeader(serializedKey);

        if (type is not (PaserkType.LocalPassword or PaserkType.SecretPassword))
            throw new PaserkNotSupportedException($"The PASERK type {type} does not support password-based unwrapping.");

        var ptk = PaserkPbkw.Decrypt(header, version, password.ToArray(), encodedKey);
        return BuildKey(type, version, ptk);
    }

    private static (PaserkType type, ProtocolVersion version, string header, string encodedKey) ParseHeader(string serializedKey)
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
        var header = serializedKey[..(serializedKey.Length - encodedKey.Length)];

        return (type, (ProtocolVersion)version, header, encodedKey);
    }

    private static PasetoKey BuildKey(PaserkType type, ProtocolVersion version, byte[] key)
    {
        var baseType = PaserkHelpers.MapWrappedType(type);
        var protocol = PaserkHelpers.CreateProtocolVersion(version);

        // No length validation here: the authentication tag already guarantees the unwrapped
        // payload is exactly what the producer wrapped, and encodings (e.g. RSA/EC secret keys)
        // vary in length across versions.
        return baseType switch
        {
            PaserkType.Local => new PasetoSymmetricKey(key, protocol),
            PaserkType.Secret => new PasetoAsymmetricSecretKey(key, protocol),
            _ => throw new PaserkInvalidException($"Unable to build a key for the PASERK type {type}."),
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