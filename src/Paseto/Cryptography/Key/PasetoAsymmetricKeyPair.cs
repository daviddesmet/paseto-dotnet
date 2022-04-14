namespace Paseto.Cryptography.Key;

using System;
using Paseto.Protocol;

/// <summary>
/// Defines a Paseto Asymmetric Key Pair.
/// </summary>
public class PasetoAsymmetricKeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasetoAsymmetricKeyPair"/> class.
    /// </summary>
    /// <param name="secretKey">The secret key.</param>
    /// <param name="publicKey">The public key.</param>
    /// <param name="protocol">The protocol version.</param>
    public PasetoAsymmetricKeyPair(ReadOnlyMemory<byte> secretKey, ReadOnlyMemory<byte> publicKey, IPasetoProtocolVersion protocol)
    {
        SecretKey = new PasetoAsymmetricSecretKey(secretKey, protocol);
        PublicKey = new PasetoAsymmetricPublicKey(publicKey, protocol);
        Protocol = protocol;
    }

    /// <summary>
    /// Gets the Paseto Asymmetric Secret Key.
    /// </summary>
    public PasetoAsymmetricSecretKey SecretKey { get; }

    /// <summary>
    /// Gets the Paseto Asymmetric Public Key.
    /// </summary>
    public PasetoAsymmetricPublicKey PublicKey { get; }

    /// <summary>
    /// Gets the Protocol version.
    /// </summary>
    public IPasetoProtocolVersion Protocol { get; }
}
