namespace Paseto.Cryptography.Key;

using System;
using Paseto.Protocol;

/// <summary>
/// Defines a Paseto Asymmetric Public Key.
/// </summary>
public class PasetoAsymmetricPublicKey : PasetoKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasetoAsymmetricPublicKey"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="protocol">The protocol version.</param>
    public PasetoAsymmetricPublicKey(ReadOnlyMemory<byte> key, IPasetoProtocolVersion protocol) : base(key, protocol) { }

    /// <inheritdoc/>
    public override bool IsValidFor(IPasetoProtocolVersion protocol, Purpose purpose) => Protocol?.Version == protocol.Version && purpose == Purpose.Public;
}
