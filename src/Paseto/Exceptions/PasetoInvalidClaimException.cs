namespace Paseto;

using System;
using System.Runtime.Serialization;

[Serializable]
public class PasetoInvalidClaimException : PasetoException
{
    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidClaimException" />.
    /// </summary>
    public PasetoInvalidClaimException() : base() { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidClaimException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    public PasetoInvalidClaimException(string message) : base(message) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidClaimException" />.
    /// </summary>
    /// <param name="message">The exception message</param>
    /// <param name="inner">The inner exception</param>
    public PasetoInvalidClaimException(string message, Exception inner) : base(message, inner) { }

    /// <summary>
    /// Creates a new instance of <see cref="PasetoInvalidClaimException" />.
    /// </summary>
    /// <param name="info">The SerializationInfo</param>
    /// <param name="context">The streaming context</param>
    protected PasetoInvalidClaimException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}