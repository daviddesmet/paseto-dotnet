namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoNotSupportedException : PasetoException
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoNotSupportedException" />.
    /// </summary>
    public PasetoNotSupportedException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoNotSupportedException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoNotSupportedException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoNotSupportedException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoNotSupportedException(string message, Exception inner) : base(message, inner) { }
}