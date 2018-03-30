namespace Paseto
{
    using System;
    using System.Collections.Generic;

    using Protocol;

    /// <summary>
    /// The Paseto Configurator.
    /// </summary>
    /// <seealso cref="Paseto.IPasetoConfigurator" />
    internal sealed class PasetoConfigurator : IPasetoConfigurator
    {
        private byte[] _key;
        private byte[] _nonce;

        /// <summary>
        /// Gets the protocol.
        /// </summary>
        /// <value>The protocol.</value>
        public IPasetoProtocol Protocol { get; private set; }

        /// <summary>
        /// Gets the purpose.
        /// </summary>
        /// <value>The purpose.</value>
        public Purpose Purpose { get; private set; }

        /// <summary>
        /// Sets the configurator to use the specified key.
        /// </summary>
        /// <typeparam name="TProtocol">The type of the paseto protocol.</typeparam>
        /// <param name="key">The secret key (for encoding) or the public key (for decoding and validating).</param>
        /// <param name="purpose">The purpose.</param>
        /// <returns>IPasetoConfigurator.</returns>
        /// <exception cref="ArgumentNullException">key</exception>
        public IPasetoConfigurator Use<TProtocol>(byte[] key, Purpose purpose = Purpose.Public) where TProtocol : IPasetoProtocol, new()
        {
            if (key is null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            Protocol = new TProtocol();
            Purpose = purpose;
            _key = key;

            return this;
        }

        /// <summary>
        /// Sets the configurator to use the specified key and nonce.
        /// </summary>
        /// <typeparam name="TProtocol">The type of the paseto protocol.</typeparam>
        /// <param name="key">The secret key (for encoding) or the public key (for decoding and validating).</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="purpose">The purpose.</param>
        /// <returns>IPasetoConfigurator.</returns>
        /// <exception cref="ArgumentNullException">key</exception>
        public IPasetoConfigurator Use<TProtocol>(byte[] key, byte[] nonce, Purpose purpose = Purpose.Local) where TProtocol : IPasetoProtocol, new()
        {
            if (key is null || key.Length == 0)
                throw new ArgumentNullException(nameof(key));

            Protocol = new TProtocol();
            Purpose = purpose;
            _key = key;
            _nonce = nonce;

            return this;
        }

        /// <summary>
        /// Encodes the specified payload and optional footer.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="NotSupportedException">The Local Purpose is not currently supported!</exception>
        /// <exception cref="NotImplementedException"></exception>
        public string Encode(PasetoPayload payload, string footer = "")
        {
            switch (Purpose)
            {
                case Purpose.Local:
                    if (Protocol is Version1)
                        throw new NotSupportedException("The Local Purpose is not currently supported in the specified Protocol!");
                    return Protocol.Encrypt(_key, _nonce, payload.SerializeToJson(), footer ?? string.Empty);
                case Purpose.Public:
                    return Protocol.Sign(_key, payload.SerializeToJson(), footer ?? string.Empty);
                default:
                    throw new NotImplementedException($"The {Purpose} Purpose is not defined!");
            }
        }

        /// <summary>
        /// Decodes the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="NotSupportedException">The Local Purpose is not currently supported!</exception>
        /// <exception cref="SignatureVerificationException">Invalid signature!</exception>
        /// <exception cref="NotImplementedException"></exception>
        public string Decode(string token)
        {
            switch (Purpose)
            {
                case Purpose.Local:
                    if (Protocol is Version1)
                        throw new NotSupportedException("The Local Purpose is not currently supported in the specified Protocol!");
                    return Protocol.Decrypt(token, _key);
                case Purpose.Public:
                    var (valid, payload) = Protocol.Verify(token, _key);
                    if (!valid)
                        throw new SignatureVerificationException("Invalid signature!");

                    return payload;
                default:
                    throw new NotImplementedException($"The {Purpose} Purpose is not defined!");
            }
        }
    }
}
