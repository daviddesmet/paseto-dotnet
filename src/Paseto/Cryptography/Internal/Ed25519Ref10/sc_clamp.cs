namespace Paseto.Cryptography.Internal.Ed25519Ref10;

using System;

internal static partial class ScalarOperations
{
    internal static void sc_clamp(Span<byte> s, int offset)
    {
        s[offset + 0] &= 248;
        s[offset + 31] &= 127;
        s[offset + 31] |= 64;
    }
}