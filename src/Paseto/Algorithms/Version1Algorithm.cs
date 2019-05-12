namespace Paseto.Algorithms
{
    using System;
    using System.Security.Cryptography;

    using Extensions;
    using static Utils.EncodingHelper;

    /// <summary>
    /// Paseto Version 2 Algorithm.
    /// </summary>
    /// <seealso cref="Paseto.Algorithms.IPasetoAlgorithm" />
    internal sealed class Version1Algorithm : IPasetoAlgorithm
    {
        /// <summary>
        /// Encrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Encrypt(string payload, byte[] aad, byte[] key, byte[] nonce) => Encrypt(GetBytes(payload), aad, key, nonce);

        /// <summary>
        /// Encrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Encrypt(byte[] payload, byte[] aad, byte[] key, byte[] nonce)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Decrypts the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="aad">The additional associated data.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.String.</returns>
        public string Decrypt(byte[] payload, byte[] aad, byte[] key, byte[] nonce)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Signs the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The secret key.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Sign(byte[] message, byte[] key)
        {
#if NETSTANDARD2_0
            using (var rsa = RSA.Create())
            {
                //rsa.KeySize = 2048; // Default
                rsa.FromCompatibleXmlString(GetString(key));

                return rsa.SignData(message, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            }
#elif (NET46 || NET47)
            using (var rsa = new RSACng())
            {
                //rsa.KeySize = 2048; // Default
                rsa.FromXmlString(GetString(key));

                return rsa.SignData(message, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            }
#endif
        }

        /// <summary>
        /// Verifies the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="key">The public key.</param>
        /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
        public bool Verify(byte[] message, byte[] signature, byte[] key)
        {
            // NOTE: Not Supported in Linux until 2.1
            //
            // Enable RSA-OAEP(SHA-2) and RSA-PSS on Unix systems #27394
            // https://github.com/dotnet/corefx/pull/27394
            // https://github.com/dotnet/corefx/issues/2522
#if NETSTANDARD2_0
            using (var rsa = RSA.Create())
            {
                //rsa.KeySize = 2048; // Default
                rsa.FromCompatibleXmlString(GetString(key));

                return rsa.VerifyData(message, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            }
#elif (NET46 || NET47)
            using (var rsa = new RSACng())
            {
                //rsa.KeySize = 2048; // Default
                rsa.FromXmlString(GetString(key));

                return rsa.VerifyData(message, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            }
#endif
        }

        /// <summary>
        /// Hashes the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="size">The size.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Hash(string payload, int size) => Hash(GetBytes(payload), size);

        /// <summary>
        /// Hashes the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="size">The size.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Hash(byte[] payload, int size)
        {
            throw new NotImplementedException();
        }
    }
}
