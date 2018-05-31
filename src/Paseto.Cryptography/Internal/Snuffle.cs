namespace Paseto.Cryptography.Internal
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Abstract base class for XSalsa20, ChaCha20, XChaCha20 and their variants.
    /// </summary>
    /// <remarks>
    /// Variants of Snuffle have two differences: the size of the nonce and the block function that
    /// produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
    /// specifying these two information by overriding <seealso cref="Paseto.Cryptography.Internal.Snuffle.NonceSizeInBytes()" /> and <seealso cref="Paseto.Cryptography.Internal.Snuffle.GetKeyStreamBlock(byte[], int)" />.
    ///
    /// Concrete implementations of this class are meant to be used to construct an Aead with <seealso cref="Paseto.Cryptography.Internal.Poly1305" />. The
    /// base class of these Aead constructions is <seealso cref="Paseto.Cryptography.Internal.SnufflePoly1305" />.
    /// For example, <seealso cref="Paseto.Cryptography.Internal.ChaCha.XChaCha20" /> is a subclass of this class and a
    /// concrete Snuffle implementation, and <seealso cref="Paseto.Cryptography.XChaCha20Poly1305" /> is
    /// a subclass of <seealso cref="Paseto.Cryptography.Internal.SnufflePoly1305" /> and a concrete Aead construction.
    /// </remarks>
    public abstract class Snuffle
    {
        public static int BLOCK_SIZE_IN_INTS = 16;
        public static int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
        public static int KEY_SIZE_IN_INTS = 8;
        public static int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

        public static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; //Encoding.ASCII.GetBytes("expand 32-byte k");

        protected readonly byte[] Key;
        private int _initialCounter;

        /// <summary>
        /// Initializes a new instance of the <see cref="Snuffle"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <exception cref="CryptographyException"></exception>
        public Snuffle(byte[] key, int initialCounter)
        {
            if (key.Length != KEY_SIZE_IN_BYTES)
                throw new CryptographyException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

            Key = key;
            _initialCounter = initialCounter;
        }

        /// <summary>
        /// Returns a key stream block from <paramref name="nonce"> and <paramref name="counter">.
        ///
        /// From this function, the Snuffle encryption function can be constructed using the counter
        /// mode of operation. For example, the ChaCha20 block function and how it can be used to
        /// construct the ChaCha20 encryption function are described in section 2.3 and 2.4 of RFC 7539.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="counter">The counter.</param>
        /// <returns>ByteBuffer.</returns>
        public abstract byte[] GetKeyStreamBlock(byte[] nonce, int counter);

        /// <summary>
        /// The size of the randomly generated nonces.
        /// ChaCha20 uses 12-byte nonces, but XSalsa20 and XChaCha20 use 24-byte nonces.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public abstract int NonceSizeInBytes();

        /// <summary>
        /// Encrypts the specified plaintext.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="nonce">The optional nonce.</param>
        /// <exception cref="CryptographyException">plaintext or ciphertext</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] nonce = null)
        {
            if (plaintext.Length > int.MaxValue - NonceSizeInBytes())
                throw new CryptographyException($"The {nameof(plaintext)} is too long.");

            var ciphertext = new byte[plaintext.Length + NonceSizeInBytes()];

            if (ciphertext.Length - NonceSizeInBytes() < plaintext.Length)
                throw new CryptographyException($"The {nameof(ciphertext)} is too short.");

            if (nonce != null && nonce.Length != NonceSizeInBytes())
                throw new CryptographyException($"The nonce length in bytes must be {NonceSizeInBytes()}.");

            if (nonce is null)
            {
                nonce = new byte[NonceSizeInBytes()];
                RandomNumberGenerator.Create().GetBytes(nonce);
            }

            Array.Copy(nonce, ciphertext, nonce.Length);
            Process(nonce, ciphertext, plaintext, nonce.Length);

            return ciphertext;
        }

        /// <summary>
        /// Decrypts the specified ciphertext.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">ciphertext</exception>
        public virtual byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext.Length < NonceSizeInBytes())
                throw new CryptographyException($"The {nameof(ciphertext)} is too short.");

            var nonce = new byte[NonceSizeInBytes()];
            Array.Copy(ciphertext, nonce, nonce.Length);
            var plaintext = new byte[ciphertext.Length - NonceSizeInBytes()];

            Process(nonce, plaintext, ciphertext.Skip(NonceSizeInBytes()).ToArray());

            return plaintext;
        }

        /// <summary>
        /// Processes the Encryption/Decryption function.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="offset">The output's starting offset.</param>
        private void Process(byte[] nonce, byte[] output, byte[] input, int offset = 0)
        {
            var length = input.Length;
            var numBlocks = (length / BLOCK_SIZE_IN_BYTES) + 1;
            for (var i = 0; i < numBlocks; i++)
            {
                var keyStream = GetKeyStreamBlock(nonce, i + _initialCounter);
                if (i == numBlocks - 1)
                    Xor(output, input, keyStream, length % BLOCK_SIZE_IN_BYTES, offset, i); // last block
                else
                    Xor(output, input, keyStream, BLOCK_SIZE_IN_BYTES, offset, i);
            }
        }

        protected static uint RotateLeft(uint x, int y) => (x << y) | (x >> (32 - y));

        /// <summary>
        /// XOR the specified output.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="keyStream">The key stream block.</param>
        /// <param name="len">The length.</param>
        /// <param name="offset">The output's starting offset.</param>
        /// <param name="curBlock">The current block number.</param>
        /// <exception cref="CryptographyException">The combination of blocks, offsets and length to be XORed is out-of-bonds.</exception>
        private static void Xor(byte[] output, byte[] input, byte[] keyStream, int len, int offset, int curBlock)
        {
            var blockOffset = curBlock * BLOCK_SIZE_IN_BYTES;

            if (len < 0 || offset < 0 || curBlock < 0 || output.Length < len || (input.Length - blockOffset) < len || keyStream.Length < len)
                throw new CryptographyException("The combination of blocks, offsets and length to be XORed is out-of-bonds.");

            for (var i = 0; i < len; i++)
                output[i + offset + blockOffset] = (byte)(input[i + blockOffset] ^ keyStream[i]);
        }
    }
}
