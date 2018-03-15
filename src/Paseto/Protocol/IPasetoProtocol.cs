namespace Paseto.Protocol
{
    /// <summary>
    /// Defines the Paseto IProtocol.
    /// </summary>
    public interface IPasetoProtocol
    {
        /// <summary>
        /// Gets the unique header version string with which the protocol can be identified.
        /// </summary>
        /// <value>The header version.</value>
        string Version { get; }

        /// <summary>
        /// Encrypt a message using a shared key.
        /// </summary>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        string Encrypt(byte[] key, byte[] nonce, string payload, string footer = "");

        /// <summary>
        /// Decrypts the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="key">The symmetric key.</param>
        /// <returns>System.String.</returns>
        string Decrypt(string token, byte[] key);

        /// <summary>
        /// Signs the specified payload.
        /// </summary>
        /// <param name="key">The secret key.</param>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        string Sign(byte[] key, string payload, string footer = "");

        /// <summary>
        /// Verifies the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="key">The public key.</param>
        /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
        (bool Valid, string Payload) Verify(string token, byte[] key);
    }
}
