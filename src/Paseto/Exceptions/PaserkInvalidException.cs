namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PaserkInvalidException : Exception
{
    /// <summary>
    /// Creates a new instance of <see cref="PaserkInvalidException" />.
    /// </summary>
    public PaserkInvalidException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PaserkInvalidException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PaserkInvalidException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PaserkInvalidException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PaserkInvalidException(string message, Exception inner) : base(message, inner) { }
}