namespace Paseto.Cryptography.Internal.ChaCha
{
    /// <summary>
    /// A stream cipher based on https://download.libsodium.org/doc/advanced/xchacha20.html
    /// 
    /// This cipher is meant to be used to construct an AEAD with Poly1305.
    /// </summary>
    /// <seealso cref="Paseto.Cryptography.Internal.ChaCha.ChaCha20Base" />
    public class XChaCha20 : ChaCha20Base
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="XChaCha20"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        public XChaCha20(byte[] key, int initialCounter) : base(key, initialCounter) { }

        /// <summary>
        /// Creates the initial state.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="counter">The counter.</param>
        /// <returns>Array16&lt;System.UInt32&gt;.</returns>
        protected override Array16<uint> CreateInitialState(byte[] nonce, int counter)
        {
            // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
            var state = new Array16<uint>();

            SetSigma(ref state);
            SetKey(ref state, HChaCha20(Key, nonce));

            // Set Nonce
            state.x12 = (uint)counter;
            state.x13 = 0;
            state.x14 = ByteIntegerConverter.LoadLittleEndian32(nonce, 4);
            state.x15 = ByteIntegerConverter.LoadLittleEndian32(nonce, 8);

            return state;
        }

        /// <summary>
        /// The size of the randomly generated nonces.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public override int NonceSizeInBytes() => 24;
    }
}
