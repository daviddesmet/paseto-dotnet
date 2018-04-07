namespace Paseto.Algorithms
{
    public interface IPasetoAlgorithm
    {
        /// <summary>
        /// Encrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        byte[] Encrypt(string payload, byte[] aad, byte[] key, byte[] nonce);

        /// <summary>
        /// Encrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        byte[] Encrypt(byte[] payload, byte[] aad, byte[] key, byte[] nonce);

        /// <summary>
        /// Decrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <returns>System.Byte[].</returns>
        string Decrypt(byte[] payload, byte[] aad, byte[] key);

        /// <summary>
        /// Signs the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The secret key.</param>
        /// <returns>System.Byte[].</returns>
        byte[] Sign(byte[] message, byte[] key);

        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="key">The public key.</param>
        /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
        bool Verify(byte[] message, byte[] signature, byte[] key);

        /// <summary>
        /// Hashes the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="size">The size.</param>
        /// <returns>System.Byte[].</returns>
        byte[] Hash(string payload, int size);

        /// <summary>
        /// Hashes the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="size">The size.</param>
        /// <returns>System.Byte[].</returns>
        byte[] Hash(byte[] payload, int size);
    }
}
