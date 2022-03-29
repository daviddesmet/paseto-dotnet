namespace Paseto.Cryptography.Key;

using System;
using System.Security.Cryptography;
using Paseto.Protocol;

/// <summary>
/// Abstract base class for Paseto Cryptographic Keys.
/// </summary>
public abstract class PasetoKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasetoKey"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="protocol">The protocol version.</param>
    /// <exception cref="CryptographicException"></exception>
    public PasetoKey(ReadOnlyMemory<byte> key, IPasetoProtocolVersion protocol)
    {
        Key = key;
        Protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
    }

    /// <summary>
    /// Gets the Key material.
    /// </summary>
    public ReadOnlyMemory<byte> Key { get; }

    /// <summary>
    /// Gets the Protocol version.
    /// </summary>
    public IPasetoProtocolVersion Protocol { get; internal set; }

    /// <summary>
    /// Determines the Key validity.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="purpose">The purpose.</param>
    /// <returns></returns>
    public abstract bool IsValidFor(IPasetoProtocolVersion protocol, Purpose purpose);

    internal void SetProtocol(IPasetoProtocolVersion protocol) => Protocol = protocol;
}
