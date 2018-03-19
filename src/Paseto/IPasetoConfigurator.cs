namespace Paseto
{
    using System;
    using System.Collections.Generic;

    using Protocol;

    public interface IPasetoConfigurator
    {
        /// <summary>
        /// Gets the protocol.
        /// </summary>
        /// <value>The protocol.</value>
        IPasetoProtocol Protocol { get; }

        /// <summary>
        /// Gets the purpose.
        /// </summary>
        /// <value>The purpose.</value>
        Purpose Purpose { get; }

        /// <summary>
        /// Sets the configurator to use the specified key.
        /// </summary>
        /// <typeparam name="TProtocol">The type of the paseto protocol.</typeparam>
        /// <param name="key">The secret key (for encoding) or the public key (for decoding and validating).</param>
        /// <param name="purpose">The purpose.</param>
        /// <returns>IPasetoConfigurator.</returns>
        IPasetoConfigurator Use<TProtocol>(byte[] key, Purpose purpose = Purpose.Public) where TProtocol : IPasetoProtocol, new();

        /// <summary>
        /// Encodes the specified payload and optional footer.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        string Encode(PasetoPayload payload, string footer = "");

        /// <summary>
        /// Decodes the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>System.String.</returns>
        string Decode(string token);
    }
}
