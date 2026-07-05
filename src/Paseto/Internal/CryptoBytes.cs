using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Paseto.Internal;

internal static class CryptoBytes
{
    internal static byte[] Combine(params byte[][] arrays)
    {
        var rv = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, rv, offset, array.Length);
            offset += array.Length;
        }
        return rv;
    }

    internal static bool ConstantTimeEquals(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        if (x.Length != y.Length)
            throw new ArgumentException("x.Length must equal y.Length");

#if NETFRAMEWORK
        // CryptographicOperations.FixedTimeEquals is unavailable on .NET Framework; use a
        // branch-free bit-difference accumulator that runs in time independent of the data.
        return InternalConstantTimeEquals(x, y) != 0;
#else
        return CryptographicOperations.FixedTimeEquals(x, y);
#endif
    }

#if NETFRAMEWORK
    private static uint InternalConstantTimeEquals(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        var differentbits = 0;
        for (var i = 0; i < x.Length; i++)
            differentbits |= x[i] ^ y[i];

        return 1 & (unchecked((uint)differentbits - 1) >> 8);
    }
#endif

    internal static void Wipe(byte[] data)
    {
        if (data is null)
            throw new ArgumentNullException(nameof(data));

        InternalWipe(data, 0, data.Length);
    }

    internal static void Wipe(ArraySegment<byte> data)
    {
        if (data.Array is null)
            throw new ArgumentNullException(nameof(data));

        InternalWipe(data.Array, data.Offset, data.Count);
    }

    // Secure wiping is hard
    // * the GC can move around and copy memory
    //   Perhaps this can be avoided by using unmanaged memory or by fixing the position of the array in memory
    // * Swap files and error dumps can contain secret information
    //   It seems possible to lock memory in RAM, no idea about error dumps
    // CryptographicOperations.ZeroMemory guarantees the write is not elided by the JIT.
    // On .NET Framework that API is unavailable, so we clear the array on a method flagged
    // NoInlining | NoOptimization so the JIT cannot drop the wipe as a dead store.
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void InternalWipe(byte[] data, int offset, int count)
    {
#if NETFRAMEWORK
        Array.Clear(data, offset, count);
#else
        CryptographicOperations.ZeroMemory(data.AsSpan(offset, count));
#endif
    }
}