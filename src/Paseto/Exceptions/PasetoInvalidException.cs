namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoInvalidException : PasetoException
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidException" />.
    /// </summary>
    public PasetoInvalidException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoInvalidException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoInvalidException(string message, Exception inner) : base(message, inner) { }
}