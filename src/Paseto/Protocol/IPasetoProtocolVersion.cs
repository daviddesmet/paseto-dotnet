namespace Paseto.Protocol;

using Paseto.Cryptography.Key;

/// <summary>
/// Defines the Paseto Protocol Version.
/// </summary>
public interface IPasetoProtocolVersion
{
    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    string Version { get; }

    /// <summary>
    /// Encrypt a message using a shared secret key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "");

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The symmetric key.</param>
    string Decrypt(string token, PasetoSymmetricKey pasetoKey);

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric secret key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "");

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    (bool Valid, string Payload) Verify(string token, PasetoAsymmetricPublicKey pasetoKey);
}
