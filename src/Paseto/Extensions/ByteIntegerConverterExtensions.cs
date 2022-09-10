namespace Paseto.Extensions;

using System;
using Paseto.Cryptography.Internal;

public static class ByteIntegerConverterExtensions
{
    public static void Array16LoadBigEndian64(out Array16<ulong> output, ReadOnlySpan<byte> input, int inputOffset)
    {
        output.x0 = LoadBigEndian64(input, inputOffset + 0);
        output.x1 = LoadBigEndian64(input, inputOffset + 8);
        output.x2 = LoadBigEndian64(input, inputOffset + 16);
        output.x3 = LoadBigEndian64(input, inputOffset + 24);
        output.x4 = LoadBigEndian64(input, inputOffset + 32);
        output.x5 = LoadBigEndian64(input, inputOffset + 40);
        output.x6 = LoadBigEndian64(input, inputOffset + 48);
        output.x7 = LoadBigEndian64(input, inputOffset + 56);
        output.x8 = LoadBigEndian64(input, inputOffset + 64);
        output.x9 = LoadBigEndian64(input, inputOffset + 72);
        output.x10 = LoadBigEndian64(input, inputOffset + 80);
        output.x11 = LoadBigEndian64(input, inputOffset + 88);
        output.x12 = LoadBigEndian64(input, inputOffset + 96);
        output.x13 = LoadBigEndian64(input, inputOffset + 104);
        output.x14 = LoadBigEndian64(input, inputOffset + 112);
        output.x15 = LoadBigEndian64(input, inputOffset + 120);
    }

    public static ulong LoadBigEndian64(ReadOnlySpan<byte> buf, int offset) => (ulong)(buf[offset + 7])
            | (((ulong)(buf[offset + 6])) << 8)
            | (((ulong)(buf[offset + 5])) << 16)
            | (((ulong)(buf[offset + 4])) << 24)
            | (((ulong)(buf[offset + 3])) << 32)
            | (((ulong)(buf[offset + 2])) << 40)
            | (((ulong)(buf[offset + 1])) << 48)
            | (((ulong)(buf[offset + 0])) << 56);
}