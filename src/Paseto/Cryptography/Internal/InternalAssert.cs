namespace Paseto.Cryptography.Internal;

using System;

internal static class InternalAssert
{
    public static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException($"An assertion in Paseto.Cryptography failed {message}!");
    }
}
