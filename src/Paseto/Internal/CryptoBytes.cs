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
        => x.Length != y.Length
            ? throw new ArgumentException("x.Length must equal y.Length")
            : CryptographicOperations.FixedTimeEquals(x, y);

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
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void InternalWipe(byte[] data, int offset, int count) => CryptographicOperations.ZeroMemory(data.AsSpan(offset, count));
}