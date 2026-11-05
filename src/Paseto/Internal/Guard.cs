namespace Paseto.Internal;

using System;

/// <summary>
/// Argument validation helpers that work uniformly across target frameworks.
/// </summary>
internal static class Guard
{
    /// <summary>
    /// Throws <see cref="ArgumentNullException"/> if <paramref name="argument"/> is <c>null</c>.
    /// Mirrors <c>ArgumentNullException.ThrowIfNull</c>, which is only available on .NET 6+.
    /// </summary>
    internal static void NotNull(object argument, string paramName)
    {
#if NETFRAMEWORK
        if (argument is null)
            throw new ArgumentNullException(paramName);
#else
        ArgumentNullException.ThrowIfNull(argument, paramName);
#endif
    }
}
