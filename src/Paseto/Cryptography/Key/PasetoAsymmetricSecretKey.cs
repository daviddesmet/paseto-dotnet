namespace Paseto.Cryptography.Key;

using System;
using Paseto.Protocol;

/// <summary>
/// Defines a Paseto Asymmetric Secret Key.
/// </summary>
public class PasetoAsymmetricSecretKey : PasetoKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasetoAsymmetricSecretKey"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="protocol">The protocol version.</param>
    public PasetoAsymmetricSecretKey(ReadOnlyMemory<byte> key, IPasetoProtocolVersion protocol) : base(key, protocol) { }

    /// <inheritdoc/>
    public override bool IsValidFor(IPasetoProtocolVersion protocol, Purpose purpose) => Protocol.Version == protocol.Version && purpose == Purpose.Public;
}
