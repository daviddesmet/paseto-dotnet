namespace Paseto
{
    using System;
    using static Utils.EncodingHelper;

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

        /// <summary>
        /// Decodes a token into a PasetoData object using the supplied dependencies.
        /// </summary>
        /// <param name="token">The Paseto token.</param>
        /// <returns>PasetoData.</returns>
        public PasetoData DecodeToObject(string token) => new PasetoData(DecodeHeader(token), PasetoPayload.DeserializeFromJson(Decode(token)), DecodeFooter(token));

        /// <summary>
        /// Decodes the header using the supplied token.
        /// </summary>
        /// <param name="token">The Paseto token.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="NotSupportedException">The specified token is not supported!</exception>
        private string DecodeHeader(string token)
        {
            var parts = token.Split('.');
            if (parts.Length < 3)
                throw new NotSupportedException("The specified token is not valid!");

            return $"{parts[0]}.{parts[1]}";
        }

        /// <summary>
        /// Decodes the footer using the supplied token.
        /// </summary>
        /// <param name="token">The Paseto token.</param>
        /// <returns>System.String.</returns>
        private string DecodeFooter(string token)
        {
            var parts = token.Split('.');
            return GetString(FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty));
        }
    }
}
