namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoVerificationException : PasetoException
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoVerificationException" />.
    /// </summary>
    public PasetoVerificationException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoVerificationException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoVerificationException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoVerificationException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoVerificationException(string message, Exception inner) : base(message, inner) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoVerificationException" />.
    /// </summary>
    /// <param name="info">The SerializationInfo</param>
    /// <param name="context">The streaming context</param>
    protected PasetoVerificationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}