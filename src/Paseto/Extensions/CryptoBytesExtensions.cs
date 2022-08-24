﻿namespace Paseto.Extensions;

using System;
using System.Runtime.CompilerServices;

public static class CryptoBytesExtensions
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void InternalWipe(Span<byte> data, int offset, int count) => data.Slice(offset, count).Clear();

    public static void Wipe(Span<byte> data)
    {
        InternalWipe(data, 0, data.Length);
    }
}