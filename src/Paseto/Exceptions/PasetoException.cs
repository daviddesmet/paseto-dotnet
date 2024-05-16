namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoException : Exception
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoException" />.
    /// </summary>
    public PasetoException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoException(string message, Exception inner) : base(message, inner) { }
}
