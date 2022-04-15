namespace Paseto.Cryptography.Key;

using System;
using Paseto.Protocol;

/// <summary>
/// Defines a Paseto Symmetric Key.
/// </summary>
public class PasetoSymmetricKey : PasetoKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasetoSymmetricKey"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="protocol">The protocol version.</param>
    public PasetoSymmetricKey(ReadOnlyMemory<byte> key, IPasetoProtocolVersion protocol) : base(key, protocol) { }

    /// <inheritdoc/>
    public override bool IsValidFor(IPasetoProtocolVersion protocol, Purpose purpose) => Protocol?.Version == protocol.Version && purpose == Purpose.Local;
}
