namespace Paseto.Builder
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Represents the Data that will store in a Paseto.
    /// </summary>
    public class PasetoData
    {
        public PasetoData() : this(null, null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasetoData"/> class.
        /// </summary>
        /// <param name="header">The header.</param>
        /// <param name="payload">The payload.</param>
        public PasetoData(string header, IDictionary<string, object> payload)
        {
            Header = header;
            Payload = payload ?? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The header information of the Paseto.
        /// </summary>
        public string Header { get; }

        /// <summary>
        /// The payload of the Paseto as a key-value store.
        /// </summary>
        public IDictionary<string, object> Payload { get; }
    }
}
