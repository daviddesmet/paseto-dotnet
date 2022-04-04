namespace Paseto.Builder;

using System;
using System.Collections.Generic;

using Paseto.Extensions;
using Paseto.Cryptography.Key;
using Paseto.Handlers;
using Paseto.Protocol;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Build and decode a Paseto using a Fluent API.
/// </summary>
public sealed class PasetoBuilder
{
    private readonly PasetoData _paseto = new();
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
        {
            Version3.VERSION,
            () => new Version3()
        }
#pragma warning restore CS0618 // Type or member is obsolete
    };

    //private IJsonSerializer _serializer = new JsonNetSerializer();
    //private IBase64UrlEncoder _urlEncoder = new Base64UrlEncoder();

    private IPasetoProtocolVersion _protocol;
    private Purpose _purpose;
    private PasetoKey _pasetoKey;
    private byte[] _nonce;
    private string _footer;
    private bool _verify;

#pragma warning disable CS0618 // Type or member is obsolete
    /// <summary>
    /// Sets the protocol version 1 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder UseV1(Purpose purpose) => UseImpl(new Version1(), purpose);

    /// <summary>
    /// Sets the protocol version 2 and the purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder UseV2(Purpose purpose) => UseImpl(new Version2(), purpose);
#pragma warning restore CS0618 // Type or member is obsolete

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
    /// Sets the paseto key.
    /// </summary>
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
    /// <param name="key">The key.</param>
    /// <param name="encryption">The encryption classification.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithKey(byte[] key, Encryption encryption)
    {
        if (_protocol is null)
            throw new PasetoBuilderException("Can't set Key. Check if you have call the 'Use' method.");

        _pasetoKey = encryption switch
        {
            Encryption.SymmetricKey => new PasetoSymmetricKey(key, _protocol),// TODO: could be null if we get rid of the above check which is what we want (to be null, not to blow up)
            Encryption.AsymmetricSecretKey => new PasetoAsymmetricSecretKey(key, _protocol),// TODO: could be null if we get rid of the above check which is what we want (to be null, not to blow up)
            Encryption.AsymmetricPublicKey => new PasetoAsymmetricPublicKey(key, _protocol),// TODO: could be null if we get rid of the above check which is what we want (to be null, not to blow up)
            _ => throw new PasetoNotSupportedException($"The encryption classification {encryption} is currently not supported."),
        };
        return this;
    }

    /// <summary>
    /// Sets the symmetric shared key used for local purpose.
    /// </summary>
    /// <param name="key">The shared key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithSharedKey(byte[] key) => WithKey(key, Encryption.SymmetricKey);

    /// <summary>
    /// Sets the asymmetric secret key used for public purpose.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithSecretKey(byte[] key) => WithKey(key, Encryption.AsymmetricSecretKey);

    /// <summary>
    /// Sets the asymmetric public key used for public purpose.
    /// </summary>
    /// <param name="key">The public key.</param>
    /// <returns>Current builder instance</returns>
    public PasetoBuilder WithPublicKey(byte[] key) => WithKey(key, Encryption.AsymmetricPublicKey);

    /// <summary>
    /// Sets the nonce for encoding the token used exclusively for testing purposes.
    /// </summary>
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
        _paseto.Payload.Add(name, value);
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
    /// Adds a footer to the Paseto.
    /// </summary>
    /// <param name="footer">The footer.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddFooter(string footer)
    {
        _footer = footer;
        return this;
    }

    /// <summary>
    /// Adds a footer to the Paseto.
    /// </summary>
    /// <param name="footer">The footer.</param>
    /// <returns>PasetoBuilder&lt;TProtocol&gt;.</returns>
    public PasetoBuilder AddFooter(PasetoPayload footer)
    {
        _footer = footer.SerializeToJson();
        return this;
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

        if (_pasetoKey is null || _pasetoKey.Key.IsEmpty)
            throw new PasetoBuilderException("Can't build a token. Check if you have call the 'WithKey' method.");

        if (_paseto.Payload is null || _paseto.Payload.Count == 0)
            throw new PasetoBuilderException("Can't build a token. Check if you have call the 'AddClaim' method.");

        var payload = _paseto.Payload.SerializeToJson();

        return _purpose switch
        {
            Purpose.Local => new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey).Encrypt(_protocol, _nonce, payload, _footer ?? string.Empty),
            Purpose.Public => new PasetoPublicPurposeHandler((PasetoAsymmetricSecretKey)_pasetoKey).Sign(_protocol, payload, _footer ?? string.Empty),
            _ => throw new PasetoNotSupportedException($"The {_purpose} purpose is not supported!"),
        };
    }

    /// <summary>
    /// Decodes a token using the supplied dependencies.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <returns>The JSON payload</returns>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'WithKey' method.</exception>
    /// <exception cref="PasetoVerificationException">Invalid signature!</exception>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public string Decode(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (_protocol is null)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'Use' method.");

        if (_pasetoKey is null || _pasetoKey.Key.IsEmpty)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'WithKey' method.");

        switch (_purpose)
        {
            case Purpose.Local:
                return new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey).Decrypt(_protocol, token);
            case Purpose.Public:
                if (!_verify) // _verify is not set, should return PasetoToken object with a verify property or always handle verify and throw if not valid?
                    return new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey).Verify(_protocol, token).Payload;

                var (valid, payload) = new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey).Verify(_protocol, token);
                if (!valid)
                    throw new PasetoVerificationException("Invalid signature!");

                return payload;
            default:
                throw new PasetoNotSupportedException($"The {_purpose} purpose is not supported!");
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
    /// <returns>The JSON payload</returns>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'Use' method.</exception>
    /// <exception cref="PasetoBuilderException">Can't decode token. Check if you have call the 'WithKey' method.</exception>
    /// <exception cref="PasetoVerificationException">Invalid signature!</exception>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public string DecodePayload(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (_protocol is null)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'Use' method.");

        if (_pasetoKey is null || _pasetoKey.Key.IsEmpty)
            throw new PasetoBuilderException("Can't decode token. Check if you have call the 'WithKey' method.");

        switch (_purpose)
        {
            case Purpose.Local:
                return new PasetoLocalPurposeHandler((PasetoSymmetricKey)_pasetoKey).Decrypt(_protocol, token);
            case Purpose.Public:
                if (!_verify) // _verify is not set, should return PasetoToken object with a verify property or always handle verify and throw if not valid?
                    return new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey).Verify(_protocol, token).Payload;

                var (valid, payload) = new PasetoPublicPurposeHandler((PasetoAsymmetricPublicKey)_pasetoKey).Verify(_protocol, token);
                if (!valid)
                    throw new PasetoVerificationException("Invalid signature!");

                return payload;
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

    /// <summary>
    /// Decodes a token into a PasetoData object using the supplied dependencies.
    /// </summary>
    /// <param name="token">The Paseto token.</param>
    /// <returns>PasetoData.</returns>
    public PasetoData DecodeToObject(string token) => new(DecodeHeader(token), PasetoPayload.DeserializeFromJson(Decode(token)), DecodeFooter(token));
}
