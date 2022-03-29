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
    /// <returns>System.String.</returns>
    public string Sign(IPasetoProtocolVersion protocol, string payload, string footer = "")
    {
        Validate(protocol);
        return protocol.Sign((PasetoAsymmetricSecretKey)PasetoKey, payload, footer);
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <param name="token">The token.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    public (bool Valid, string Payload) Verify(IPasetoProtocolVersion protocol, string token)
    {
        Validate(protocol);
        return protocol.Verify(token, (PasetoAsymmetricPublicKey)PasetoKey);
    }
}
