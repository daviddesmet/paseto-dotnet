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
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    public string Encrypt(IPasetoProtocolVersion protocol, string payload, string footer = "", string assertion = "")
    {
        Validate(protocol);
        return protocol.Encrypt((PasetoSymmetricKey)PasetoKey, payload, footer, assertion);
    }

    /// <summary>
    /// Encrypt a message using a shared symmetric key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="nonce">The nonce used exclusively for testing purposes.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    internal string Encrypt(IPasetoProtocolVersion protocol, byte[] nonce, string payload, string footer = "", string assertion = "")
    {
        if (nonce is not null && nonce.Length > 0)
            ((PasetoProtocolVersion)protocol).SetTestNonce(nonce);

        return Encrypt(protocol, payload, footer, assertion);
    }

    /// <summary>
    /// Decrypts the specified token using a shared symmetric key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(IPasetoProtocolVersion protocol, string token, string footer = "", string assertion = "")
    {
        Validate(protocol);
        return protocol.Decrypt((PasetoSymmetricKey)PasetoKey, token, footer, assertion);
    }
}
