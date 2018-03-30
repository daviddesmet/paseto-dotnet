namespace Paseto.Cryptography
{
    using System;

    public class CryptographyException : Exception
    {
        public CryptographyException() { }

        public CryptographyException(string message) : base(message) { }

        public CryptographyException(string message, Exception inner) : base(message, inner) { }
    }
}
