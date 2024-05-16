namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PaserkNotSupportedException : Exception
{
    /// <summary>
    /// Creates a new instance of <see cref="PaserkNotSupportedException" />.
    /// </summary>
    public PaserkNotSupportedException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PaserkNotSupportedException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PaserkNotSupportedException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PaserkNotSupportedException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PaserkNotSupportedException(string message, Exception inner) : base(message, inner) { }
}