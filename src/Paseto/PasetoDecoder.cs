namespace Paseto
{
    using System;

    /// <summary>
    /// The Paseto Decoder.
    /// </summary>
    public sealed class PasetoDecoder
    {
        private readonly IPasetoConfigurator _config;

        /// <summary>
        /// Initializes a new instance of the <see cref="PasetoDecoder"/> class.
        /// </summary>
        /// <param name="config">The PasetoConfigurator.</param>
        public PasetoDecoder(Func<IPasetoConfigurator, IPasetoConfigurator> config) => _config = config.Invoke(new PasetoConfigurator());

        /// <summary>
        /// Decodes the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>System.String.</returns>
        public string Decode(string token) => _config.Decode(token);
    }
}
