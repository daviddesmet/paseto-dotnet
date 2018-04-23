namespace Paseto.Cryptography.Internal
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// An AEAD construction with a <see cref="Snuffle"/> and <see cref="Poly1305"/>, following RFC 7539, section 2.8.
    ///
    /// This implementation produces ciphertext with the following format: {nonce || actual_ciphertext || tag} and only decrypts the same format.
    /// </summary>
    public abstract class SnufflePoly1305
    {
        private byte[] _key;
        private Snuffle _snuffle;
        private Snuffle _macKeySnuffle;

        /// <summary>
        /// Initializes a new instance of the <see cref="SnufflePoly1305"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public SnufflePoly1305(byte[] key)
        {
            _key = key.ToArray();
            _snuffle = CreateSnuffleInstance(key, 1);
            _macKeySnuffle = CreateSnuffleInstance(key, 0);
        }

        /// <summary>
        /// Creates the snuffle instance.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <returns>Snuffle.</returns>
        protected abstract Snuffle CreateSnuffleInstance(byte[] key, int initialCounter);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> with <see cref="Poly1305"/> authentication based on <paramref name="associatedData">.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">plaintext</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] associatedData = null)
        {
            if (plaintext is null)
                throw new ArgumentNullException(nameof(plaintext));

            if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new CryptographyException($"The {nameof(plaintext)} is too long.");

            return Encrypt(plaintext, associatedData, null);
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> with <see cref="Poly1305"/> authentication based on <paramref name="associatedData">.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <param name="nonce">The nonce.</param>
        /// <exception cref="CryptographyException">output</exception>
        public byte[] Encrypt(byte[] plaintext, byte[] associatedData, byte[] nonce = null)
        {
            var output = new byte[plaintext.Length + _snuffle.NonceSizeInBytes() + Poly1305.MAC_TAG_SIZE_IN_BYTES];

            if (output.Length < plaintext.Length + _snuffle.NonceSizeInBytes() + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new CryptographyException($"The {nameof(output)} is too short.");

            if (nonce != null && nonce.Length != _snuffle.NonceSizeInBytes())
                throw new CryptographyException($"The nonce length in bytes must be {_snuffle.NonceSizeInBytes()}.");

            if (nonce is null)
            {
                nonce = new byte[_snuffle.NonceSizeInBytes()];
                RandomNumberGenerator.Create().GetBytes(nonce);
            }

            _snuffle.Encrypt(plaintext, output, nonce);
            
            //Array.Copy(output, nonce, nonce.Length); // no longer needed...

            var aad = associatedData;
            if (aad is null)
                aad = new byte[0];

            var limit = output.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES;
            var tag = Poly1305.ComputeMac(GetMacKey(nonce), MacDataRfc7539(aad, output, limit));

            Array.Copy(tag, 0, output, limit, tag.Length);
            return output;
        }

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> with <see cref="Poly1305"/> authentication based on <paramref name="associatedData">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="ArgumentNullException">ciphertext</exception>
        /// <exception cref="CryptographyException">
        /// ciphertext
        /// or
        /// AEAD Bad Tag Exception
        /// </exception>
        public virtual byte[] Decrypt(byte[] ciphertext, byte[] associatedData)
        {
            if (ciphertext is null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (ciphertext.Length < _snuffle.NonceSizeInBytes() + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new CryptographyException($"The {nameof(ciphertext)} is too short.");

            var limit = ciphertext.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES;

            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            Array.Copy(ciphertext, limit, tag, 0, tag.Length);

            var nonce = new byte[_snuffle.NonceSizeInBytes()];
            Array.Copy(ciphertext, 0, nonce, 0, nonce.Length);

            var aad = associatedData;
            if (aad == null)
                aad = new byte[0];

            try
            {
                Poly1305.VerifyMac(GetMacKey(nonce), MacDataRfc7539(aad, ciphertext, limit), tag);
            }
            catch (Exception ex)
            {
                throw new CryptographyException("AEAD Bad Tag Exception", ex);
            }

            return _snuffle.Decrypt(ciphertext.Take(limit).ToArray());
        }

        /// <summary>
        /// The MAC key is the first 32 bytes of the first key stream block.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        private byte[] GetMacKey(byte[] nonce)
        {
            var firstBlock = _macKeySnuffle.GetKeyStreamBlock(nonce, 0);
            var result = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            Array.Copy(firstBlock, result, result.Length);
            return result;
        }

        /// <summary>
        /// Prepares the input to MAC, following RFC 7539, section 2.8.
        /// </summary>
        /// <param name="aad">The aad.</param>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="len">The ciphertext's maximum length.</param>
        /// <returns>System.Byte[].</returns>
        private byte[] MacDataRfc7539(byte[] aad, byte[] ciphertext, int len)
        {
            var aadPaddedLen = (aad.Length % 16 == 0) ? aad.Length : (aad.Length + 16 - aad.Length % 16);
            var ciphertextLen = len - _snuffle.NonceSizeInBytes();
            var ciphertextPaddedLen = (ciphertextLen % 16 == 0) ? ciphertextLen : (ciphertextLen + 16 - ciphertextLen % 16);

            var macData = new byte[aadPaddedLen + ciphertextPaddedLen + 16];

            // Mac Text
            Array.Copy(aad, macData, aad.Length);
            Array.Copy(ciphertext, 0, macData, aadPaddedLen, ciphertextLen);

            // Mac Length
            //macData[aadPaddedLen + ciphertextPaddedLen] = (byte)aad.Length;
            //macData[aadPaddedLen + ciphertextPaddedLen + 8] = (byte)ciphertextLen;
            SetMacLength(macData, aadPaddedLen + ciphertextPaddedLen, aad.Length);
            SetMacLength(macData, aadPaddedLen + ciphertextPaddedLen + sizeof(ulong), ciphertextLen);

            return macData;
        }

        private void SetMacLength(byte[] macData, int offset, int value)
        {
            var lenData = new byte[8];
            ByteIntegerConverter.StoreLittleEndian64(lenData, 0, (ulong)value);

            Array.Copy(lenData, 0, macData, offset, lenData.Length);
        }
    }
}
