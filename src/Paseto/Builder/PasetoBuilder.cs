namespace Paseto.Builder;

using System;
using System.Collections.Generic;

using Paseto.Extensions;
using Paseto.Cryptography.Key;
using Paseto.Handlers;
using Paseto.Protocol;
using Paseto.Serializers;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Build and decode a Paseto using a Fluent API.
/// </summary>
public sealed class PasetoBuilder
{
    private readonly PasetoPayload _payload = new();
    private readonly Dictionary<string, Func<IPasetoProtocolVersion>> _supportedVersions = new()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        {
            Version1.VERSION,
            () => new Version1()
        },
        {
            Version2.VERSION,
            () => new Version2()
        },
#pragma warning restore CS0618 // Type or member is obsolete
        {
            Version3.VERSION,
            () => new Version3()
        },
        {
            Version4.VERSION,
            () => new Version4()
        }
    };

    private IJsonSerializer _serializer = new JsonNetSerializer();
    //private IBase64UrlEncoder _urlEncoder = new Base64UrlEncoder();

    private IPasetoProtocolVersion _protocol;
    private Purpose _purpose;
    private PasetoKey _pasetoKey;
    private byte[] _nonce;
    private string _footer;
    private string _assertion;

#pragma warning disable CS0618 // Type or member is obsolete
    /// <summary>
    /// Sets the protocol version 1 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    [Obsolete("PASETO Version 1 is deprecated. Implementations should migrate to Version 3.")]
    public PasetoBuilder UseV1(Purpose purpose) => UseImpl(new Version1(), purpose);

    /// <summary>
    /// Sets the protocol version 2 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    [Obsolete("PASETO Version 2 is deprecated. Implementations should migrate to Version 4.")]
    public PasetoBuilder UseV2(Purpose purpose) => UseImpl(new Version2(), purpose);
#pragma warning restore CS0618 // Type or member is obsolete

    /// <summary>
    /// Sets the protocol version 3 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder UseV3(Purpose purpose) => UseImpl(new Version3(), purpose);

    /// <summary>
    /// Sets the protocol version 4 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder UseV4(Purpose purpose) => UseImpl(new Version4(), purpose);

    /// <summary>
    /// Sets the protocol version and the purpose.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol version, can be custom.</typeparam>
    /// <param name="purpose">The purpose.</param>
    /// <returns></returns>
    public PasetoBuilder Use<TProtocol>(Purpose purpose) where TProtocol : IPasetoProtocolVersion, new() => UseImpl(new TProtocol(), purpose);

    /// <summary>
    /// Sets the protocol version and the purpose.
    /// </summary>
    /// <param name="version">The protocol version.</param>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public PasetoBuilder Use(ProtocolVersion version, Purpose purpose)
    {
        if (!_supportedVersions.TryGetValue(version.ToDescription(), out var proto))
            throw new PasetoNotSupportedException($"The protocol version {version} is currently not supported.");

        return UseImpl(proto(), purpose);
    }

    /// <summary>
    /// Sets the protocol version and the purpose.
    /// </summary>
    /// <param name="version">The protocol version.</param>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public PasetoBuilder Use(string version, Purpose purpose)
    {
        if (!_supportedVersions.TryGetValue(version, out var proto))
            throw new PasetoNotSupportedException($"The protocol version {version} is currently not supported.");

        return UseImpl(proto(), purpose);
    }

    private PasetoBuilder UseImpl(IPasetoProtocolVersion protocol, Purpose purpose)
    {
        _protocol = protocol;
        _purpose = purpose;
        _pasetoKey?.SetProtocol(protocol);
        return this;
    }

    /// <summary>
    /// Sets the custom JSON serializer to use.
    /// </summary>
    /// <param name="serializer">The custom JSON serializer to use.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithJsonSerializer(IJsonSerializer serializer)
    {
        _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
        _payload.SetSerializer(_serializer);
        return this;
    }

    /// <summary>
    /// Sets the paseto key.
    /// </summary>
    /// <remarks>
    /// Use for encoding and/or decoding the Paseto Token.
    /// </remarks>
    /// <param name="pasetoKey">The paseto key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithKey(PasetoKey pasetoKey)
    {
        _pasetoKey = pasetoKey;
        return this;
    }

    /// <summary>
    /// Sets the key used for the specific encryption classification.
    /// A private secret key (for encoding) or a public key (for decoding and validating) the Paseto Token.
    /// </summary>
    /// <remarks>
    /// Use for encoding and/or decoding the Paseto Token.
    /// </remarks>
    /// <param name="key">The key.</param>
    /// <param name="encryption">The encryption classification.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithKey(byte[] key, Encryption encryption)
    {
        _pasetoKey = encryption switch
        {
            Encryption.SymmetricKey => new PasetoSymmetricKey(key, _protocol),
            Encryption.AsymmetricSecretKey => new PasetoAsymmetricSecretKey(key, _protocol),
            Encryption.AsymmetricPublicKey => new PasetoAsymmetricPublicKey(key, _protocol),
            _ => throw new PasetoNotSupportedException($"The encryption classification {encryption} is currently not supported."),
        };
        _pasetoKey.SetProtocol(_protocol);
        return this;
    }

    /// <summary>
    /// Sets the symmetric shared key used for local purpose.
    /// </summary>
    /// <remarks>
    /// Use for encoding and/or decoding the Paseto Token.
    /// </remarks>
    /// <param name="key">The shared key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithSharedKey(byte[] key) => WithKey(key, Encryption.SymmetricKey);

    /// <summary>
    /// Sets the asymmetric secret key used for public purpose.
    /// </summary>
    /// <remarks>
    /// Use for encoding and/or decoding the Paseto Token.
    /// </remarks>
    /// <param name="key">The secret key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithSecretKey(byte[] key) => WithKey(key, Encryption.AsymmetricSecretKey);

    /// <summary>
    /// Sets the asymmetric public key used for public purpose.
    /// </summary>
    /// <remarks>
    /// Use for encoding and/or decoding the Paseto Token.
    /// </remarks>
    /// <param name="key">The public key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithPublicKey(byte[] key) => WithKey(key, Encryption.AsymmetricPublicKey);

    /// <summary>
    /// Sets the nonce for encoding the token used exclusively for testing purposes.
    /// </summary>
    /// <remarks>
    /// Use exclusively for testing purposes.
    /// </remarks>
    /// <param name="nonce">The nonce used exclusively for testing purposes.</param>
    /// <returns>Current builder instance</returns>
    internal PasetoBuilder WithNonce(byte[] nonce)
    {
        _nonce = nonce;
        return this;
    }

    /// <summary>
    /// Adds a claim to the Paseto.
    /// </summary>
    /// <param name="name">Claim name.</param>
    /// <param name="value">Claim value.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder AddClaim(string name, object value)
    {
        _payload.Add(name, value);
        return this;
    }

    /// <summary>
    /// Add string claim to the Paseto.
    /// </summary>
    /// <param name="name">Claim name.</param>
    /// <param name="value">Claim value.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder AddClaim(string name, string value) => AddClaim(name, (object)value);

    /// <summary>
    /// Adds well-known claim to the Paseto.
    /// </summary>
    /// <param name="name">Well-known registered claim name.</param>
    /// <param name="value">Claim value.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder AddClaim(RegisteredClaims name, string value) => AddClaim(name.GetRegisteredClaimName(), value);

    /// <summary>
    /// Adds well-known claim to the Paseto.
    /// </summary>
    /// <param name="name">Well-known registered claim name.</param>
    /// <param name="value">Claim value.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder AddClaim(RegisteredClaims name, object value) => AddClaim(name.GetRegisteredClaimName(), value);

    /// <summary>
    /// Adds a raw footer to the Paseto.
    /// </summary>
    /// <param name="footer">The raw footer.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddFooter(string footer)
    {
        _footer = footer;
        return this;
    }

    /// <summary>
    /// Adds a footer payload to the Paseto.
    /// </summary>
    /// <param name="footer">The footer payload.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddFooter(PasetoPayload footer)
    {
        footer.SetSerializer(_serializer);

        _footer = footer.ToJson();
        return this;
    }

    /// <summary>
    /// Adds a raw implicit assertion to the Paseto.
    /// </summary>
    /// <param name="assertion">The raw implicit assertion.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddImplicitAssertion(string assertion)
    {
        _assertion = assertion;
        return this;
    }

    /// <summary>
    /// Adds a implicit assertion payload to the Paseto.
    /// </summary>
    /// <param name="assertion">The implicit assertion payload.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddImplicitAssertion(PasetoPayload assertion)
    {
        assertion.SetSerializer(_serializer);

        _assertion = assertion.ToJson();
        return this;
    }

    /// <summary>
    /// Generates a random symmetric key using the specified protocol version.
    /// </summary>
    /// <remarks>
    /// Ignores the supplied keys as it generates a new random symmetric key.
    /// </remarks>
    /// <returns></returns>
    /// <exception cref="PasetoBuilderException">Can't generate serialized key. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't generate symmetric key. Specified purpose is not compatible.</exception>
    public PasetoSymmetricKey GenerateSymmetricKey()
    {
        if (_protocol is null)
            throw new PasetoBuilderException("Can't generate serialized key. Check if you have call the 'Use' method.");

        if (_purpose == Purpose.Public)
            throw new PasetoBuilderException($"Can't generate symmetric key. {_purpose} purpose is not compatible.");

        return _protocol.GenerateSymmetricKey();
    }

    /// <summary>
    /// Generates an asymmetric key pair using the supplied dependencies.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="PasetoBuilderException">Can't generate serialized key. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't generate symmetric key. Specified purpose is not compatible.</exception>
    public PasetoAsymmetricKeyPair GenerateAsymmetricKeyPair(byte[] seed = null)
    {
        if (_protocol is null)
            throw new PasetoBuilderException("Can't generate serialized key. Check if you have call the 'Use' method.");

        if (_purpose == Purpose.Local)
            throw new PasetoBuilderException($"Can't generate symmetric key. {_purpose} purpose is not compatible.");

        return _protocol.GenerateAsymmetricKeyPair(seed);
    }

    /// <summary>
    /// Generates a serialized key in PASERK format.
    /// </summary>
    /// <param name="type">The PASERK type.</param>
    /// <returns>The encoded serialized key in PASERK format.</returns>
    /// <exception cref="PasetoBuilderException">Can't generate PASERK serialized key. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't generate PASERK serialized key. Check if you have call the 'WithKey' method.</exception>
    public string GenerateSerializedKey(PaserkType type)
    {
        if (_protocol is null)
            throw new PasetoBuilderException("Can't generate PASERK serialized key. Check if you have call the 'Use' method.");

        if (_pasetoKey is null)
            throw new PasetoBuilderException("Can't generate PASERK serialized key. Check if you have call the 'WithKey' method.");

        return Paserk.Encode(_pasetoKey, type);
    }

    /// <summary>
    /// Builds a token using the supplied dependencies.
    /// </summary>
    /// <returns>The generated Paseto token.</returns>
    /// <exception cref="PasetoBuilderException">Can't build a token. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't build a token. Check if you have call the 'WithKey' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't build a token. Check if you have call the 'AddClaim' method.</exception>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public string Encode()
    {
        if (_protocol is null)
            throw new PasetoBuilderException("Can't build a token. Check if you have call the 'Use' method.");

        if (_pasetoKey is null)
            throw new PasetoBuilderException("Can't build a token. Check if you have call the 'WithKey' method.");

        if (_payload is null || _payload.Count == 0)
            throw new PasetoBuilderException("Can't build a token. Check if you have call the 'AddClaim' method.");

        var payload = _payload.ToJson();

        return _purpose switch
        {
            Purpose.Local => new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey).Encrypt(_protocol, _nonce, payload, _footer ?? string.Empty, _assertion ?? string.Empty),
            Purpose.Public => new PasetoPublicPurposeHandler((PasetoAsymmetricSecretKey)_pasetoKey).Sign(_protocol, payload, _footer ?? string.Empty, _assertion ?? string.Empty),
            _ => throw new PasetoNotSupportedException($"The {_purpose} purpose is not supported!"),
        };
    }

    /// <summary>
    /// Decodes a token using the supplied dependencies.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <param name="validationParameters">The token validation parameters.</param>
    /// <returns>a <see cref="PasetoTokenValidationResult"/> that represents a PASETO token validation operation.</returns>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'WithKey' method.</exception>
    public PasetoTokenValidationResult Decode(string token, PasetoTokenValidationParameters validationParameters = null)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (_protocol is null)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'Use' method.");

        if (_pasetoKey is null || _pasetoKey.Key.IsEmpty)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'WithKey' method.");

        validationParameters ??= new PasetoTokenValidationParameters();

        try
        {
            switch (_purpose)
            {
                case Purpose.Local:
                    var localHandler = new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey);
                    var payload = localHandler.Decrypt(_protocol, token, _footer ?? string.Empty, _assertion ?? string.Empty);
                    return localHandler.ValidateTokenPayload(new PasetoToken(token, payload), validationParameters);
                case Purpose.Public:
                    var publicHandler = new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey);
                    var result = publicHandler.Verify(_protocol, token, _footer ?? string.Empty, _assertion ?? string.Empty);
                    return !result.IsValid
                        ? PasetoTokenValidationResult.Failed(new PasetoTokenValidationException("The token signature is not valid"))
                        : publicHandler.ValidateTokenPayload(new PasetoToken(token, result.Payload), validationParameters);

                default:
                    return PasetoTokenValidationResult.Failed(new PasetoNotSupportedException($"The {_purpose} purpose is not supported"));
            }
        }
        catch (Exception ex)
        {
            return PasetoTokenValidationResult.Failed(ex);
        }
    }

    /// <summary>
    /// Decodes the header using the supplied token.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="PasetoInvalidException">The specified token has an invalid number of segments</exception>
    public string DecodeHeader(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 3)
            throw new PasetoInvalidException("The specified token has an invalid number of segments");

        return $"{parts[0]}.{parts[1]}";
    }

    /// <summary>
    /// Decodes the payload using the supplied dependencies.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <param name="validationParameters">The token validation parameters.</param>
    /// <returns>The JSON payload</returns>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'WithKey' method.</exception>
    /// <exception cref="PasetoTokenValidationException">The token signature is not valid or a claim is not valid</exception>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public string DecodePayload(string token, PasetoTokenValidationParameters validationParameters = null)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (_protocol is null)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'Use' method.");

        if (_pasetoKey is null || _pasetoKey.Key.IsEmpty)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'WithKey' method.");

        validationParameters ??= new PasetoTokenValidationParameters();

        switch (_purpose)
        {
            case Purpose.Local:
                var localHandler = new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey);
                var payload = localHandler.Decrypt(_protocol, token, _footer ?? string.Empty, _assertion ?? string.Empty);
                var localResult = localHandler.ValidateTokenPayload(new PasetoToken(token, payload), validationParameters);
                if (!localResult.IsValid)
                    throw localResult.Exception;

                return payload;
            case Purpose.Public:
                var publicHandler = new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey);
                var result = publicHandler.Verify(_protocol, token, _footer ?? string.Empty, _assertion ?? string.Empty);
                if (!result.IsValid)
                    throw new PasetoTokenValidationException("The token signature is not valid");

                var publicResult = publicHandler.ValidateTokenPayload(new PasetoToken(token, result.Payload), validationParameters);
                if (!publicResult.IsValid)
                    throw publicResult.Exception;

                return result.Payload;
            default:
                throw new PasetoNotSupportedException($"The {_purpose} purpose is not supported!");
        }
    }

    /// <summary>
    /// Decodes the footer using the supplied token.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <returns>System.String.</returns>
    public string DecodeFooter(string token)
    {
        var parts = token.Split('.');
        return GetString(FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty));
    }
}
