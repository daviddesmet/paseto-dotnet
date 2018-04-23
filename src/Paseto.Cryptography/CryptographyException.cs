namespace Paseto.Cryptography
{
    using System;

    /// <summary>
    /// Represents a cryptography exception.
    /// </summary>
    /// <seealso cref="System.Exception" />
    public class CryptographyException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographyException"/> class.
        /// </summary>
        public CryptographyException() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographyException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public CryptographyException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographyException"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="inner">The inner.</param>
        public CryptographyException(string message, Exception inner) : base(message, inner) { }
    }
}
