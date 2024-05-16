namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoBuilderException : PasetoException
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoBuilderException" />.
    /// </summary>
    public PasetoBuilderException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoBuilderException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoBuilderException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoBuilderException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoBuilderException(string message, Exception inner) : base(message, inner) { }
}
