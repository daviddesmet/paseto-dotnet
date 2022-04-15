namespace Paseto.Handlers;

using Paseto.Cryptography.Key;
using Paseto.Protocol;

/// <summary>
/// Paseto Public Purpose Handler.
/// </summary>
public class PasetoPublicPurposeHandler : PasetoPurposeHandler
{
    public PasetoPublicPurposeHandler(PasetoKey pasetoKey) : base(pasetoKey) { }

    public override Purpose Purpose => Purpose.Public;

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    public string Sign(IPasetoProtocolVersion protocol, string payload, string footer = "", string assertion = "")
    {
        Validate(protocol);
        return protocol.Sign((PasetoAsymmetricSecretKey)PasetoKey, payload, footer, assertion);
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>a <see cref="PasetoVerifyResult"/> that represents a PASETO token verify operation.</returns>
    public PasetoVerifyResult Verify(IPasetoProtocolVersion protocol, string token, string footer = "", string assertion = "")
    {
        Validate(protocol);
        return protocol.Verify((PasetoAsymmetricPublicKey)PasetoKey, token, footer, assertion);
    }
}
