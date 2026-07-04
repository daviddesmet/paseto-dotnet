namespace Paseto;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

[Serializable]
public class PasetoBuilderException : PasetoException
{
    /// <summary>
    /// Throws a <see cref="PasetoBuilderException" /> with the given <paramref name="message" /> if
    /// <paramref name="argument" /> is <c>null</c>.
    /// </summary>
    /// <param name="argument">The reference to check.</param>
    /// <param name="message">The exception message.</param>
    public static void ThrowIfNull([NotNull] object argument, string message)
    {
        if (argument is null)
            throw new PasetoBuilderException(message);
    }

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
