namespace Paseto.Algorithms
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;

    using Cryptography;
    using static Utils.EncodingHelper;

    /// <summary>
    /// Paseto Version 2 Algorithm.
    /// </summary>
    /// <seealso cref="Paseto.Algorithms.IPasetoAlgorithm" />
    internal sealed class Version2Algorithm : IPasetoAlgorithm
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

            /* 
             * Sodium
             * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
             * 
            return SecretAead.Encrypt(payload, nonce, key, aad);
            */

            /* 
             * NSec
             * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
             * 
            var algo = new XChaCha20Poly1305();
            using (var k = Key.Import(algo, key, KeyBlobFormat.RawSymmetricKey))
                return algo.Encrypt(k, new Nonce(nonce, 0), aad, payload);
            */
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

            /* 
             * Sodium
             * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
             * 
            return GetString(SecretAead.Decrypt(payload, nonce, key, associatedData));
            */

            /* 
             * NSec
             * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
             * 
            var algo = new XChaCha20Poly1305();
            using (var k = Key.Import(algo, key, KeyBlobFormat.RawSymmetricKey))
                return GetString(algo.Decrypt(k, new Nonce(nonce, 0), aad, payload));
            */
        }

        /// <summary>
        /// Signs the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The secret key.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] Sign(byte[] message, byte[] key)
        {
            // Using Paseto Cryptography library
            return Ed25519.Sign(message, key);

            /* 
             * Using NSec library
             * 
            var algo = new Ed25519();
            using (var k = Key.Import(algo, key, KeyBlobFormat.RawPrivateKey))
            {
                return algo.Sign(k, message);
            }
            */

            // Using Sodium Core library
            //return PublicKeyAuth.SignDetached(message, key);
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
            // Using Paseto Cryptography library
            return Ed25519.Verify(signature, message, key);

            /* 
             * Using NSec library
             * 
            var algo = new Ed25519();
            var publicKey = PublicKey.Import(algo, key, KeyBlobFormat.RawPublicKey);
            algo.Verify(publicKey, message, signature);
            */

            // Using Sodium Core library
            //return PublicKeyAuth.VerifyDetached(signature, message, key);
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
            var nKey = new byte[size];

            //using (var random = new RNGCryptoServiceProvider())
            //    random.GetBytes(nKey);

            RandomNumberGenerator.Create().GetBytes(nKey);

            // Using Paseto Cryptography library
            using (var hash = new Blake2B())
                return hash.ComputeHash(nKey);

            /*
             * Using NSec library
             * 
            var algo = new Blake2bMac();
            using (var key = Key.Import(algo, nKey, KeyBlobFormat.RawSymmetricKey))
                return algo.Mac(key, payload, size);
            */

            // Using Sodium Core library
            //var hash = new GenericHash.GenericHashAlgorithm(nKey, size);
            //return hash.ComputeHash(GetBytes(payload));
        }
    }
}
