namespace Paseto
{
    /// <summary>
    /// Represents the Data that will store in a Paseto.
    /// </summary>
    public class PasetoData
    {
        public PasetoData() : this(null, null, null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasetoData" /> class.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The footer.</param>
        public PasetoData(string header, PasetoPayload payload, string footer)
        {
            Header = header;
            Payload = payload ?? new PasetoPayload();//payload ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            Footer = footer;
        }

        /// <summary>
        /// The header information of the Paseto.
        /// </summary>
        public string Header { get; }

        /// <summary>
        /// The payload of the Paseto as a key-value store.
        /// </summary>
        public PasetoPayload Payload { get; }

        /// <summary>
        /// The footer information of the Paseto.
        /// </summary>
        public string Footer { get; }
    }
}
