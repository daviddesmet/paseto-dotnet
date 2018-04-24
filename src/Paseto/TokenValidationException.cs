namespace Paseto
{
    using System;

    /// <summary>
    /// Represents an exception thrown when a payload validation fails.
    /// </summary>
    public class TokenValidationException : Exception
    {
        private const string ExpectedKey = "Expected";
        private const string ReceivedKey = "Received";

        /// <summary>
        /// Creates an instance of <see cref="TokenValidationException" />.
        /// </summary>
        /// <param name="message">The error message.</param>
        public TokenValidationException(string message) : base(message) { }

        /// <summary>
        /// Expected key.
        /// </summary>
        public object Expected
        {
            get => GetOrDefault<object>(ExpectedKey);
            internal set => Data.Add(ExpectedKey, value);
        }

        /// <summary>
        /// Received key.
        /// </summary>
        public object Received
        {
            get => GetOrDefault<object>(ReceivedKey);
            internal set => Data.Add(ReceivedKey, value);
        }

        /// <summary>
        /// Retrieves the value for the provided key, or default.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        protected T GetOrDefault<T>(string key) => Data.Contains(key) ? (T)Data[key] : default(T);
    }
}
