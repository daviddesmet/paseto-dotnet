namespace Paseto.Handlers;

using Paseto.Cryptography.Key;
using Paseto.Protocol;

/// <summary>
/// Paseto Local Purpose Handler.
/// </summary>
public class PasetoLocalPurposeHandler : PasetoPurposeHandler
{
    public PasetoLocalPurposeHandler(PasetoSymmetricKey pasetoKey) : base(pasetoKey) { }

    public override Purpose Purpose => Purpose.Local;

    /// <summary>
    /// Encrypt a message using a shared symmetric key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    public string Encrypt(IPasetoProtocolVersion protocol, string payload, string footer = "")
    {
        Validate(protocol);
        return protocol.Encrypt((PasetoSymmetricKey)PasetoKey, payload, footer);
    }

    /// <summary>
    /// Encrypt a message using a shared symmetric key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="nonce">The nonce used exclusively for testing purposes.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    internal string Encrypt(IPasetoProtocolVersion protocol, byte[] nonce, string payload, string footer = "")
    {
        if (nonce is not null && nonce.Length > 0)
            ((PasetoProtocolVersion)protocol).SetTestNonce(nonce);

        return Encrypt(protocol, payload, footer);
    }

    /// <summary>
    /// Decrypts the specified token using a shared symmetric key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="token">The token.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(IPasetoProtocolVersion protocol, string token)
    {
        Validate(protocol);
        return protocol.Decrypt(token, (PasetoSymmetricKey)PasetoKey);
    }
}
