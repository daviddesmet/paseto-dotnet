namespace Paseto
{
    using System;

    /// <summary>
    /// The Paseto Encoder.
    /// </summary>
    public sealed class PasetoEncoder
    {
        private readonly IPasetoConfigurator _config;

        /// <summary>
        /// Initializes a new instance of the <see cref="PasetoEncoder"/> class.
        /// </summary>
        /// <param name="config">The PasetoConfigurator.</param>
        public PasetoEncoder(Func<IPasetoConfigurator, IPasetoConfigurator> config) => _config = config.Invoke(new PasetoConfigurator());

        /// <summary>
        /// Encodes the specified payload.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        public string Encode(PasetoPayload payload, string footer = "") => _config.Encode(payload, footer);
    }
}
