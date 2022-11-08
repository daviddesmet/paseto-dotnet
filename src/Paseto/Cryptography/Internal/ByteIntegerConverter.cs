namespace Paseto.Cryptography.Internal;

using System;
using System.Buffers.Binary;

// Loops? Arrays? Never heard of that stuff
// Library avoids unnecessary heap allocations and unsafe code
// so this ugly code becomes necessary :(
internal static class ByteIntegerConverter
{
    #region Array16

    public static void Array16LoadBigEndian64(out Array16<ulong> output, ReadOnlySpan<byte> input, int inputOffset)
    {
        output.x0 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(inputOffset));
        output.x1 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(8 + inputOffset));
        output.x2 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(16 + inputOffset));
        output.x3 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(24 + inputOffset));
        output.x4 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(32 + inputOffset));
        output.x5 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(40 + inputOffset));
        output.x6 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(48 + inputOffset));
        output.x7 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(56 + inputOffset));
        output.x8 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(64 + inputOffset));
        output.x9 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(72 + inputOffset));
        output.x10 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(80 + inputOffset));
        output.x11 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(88 + inputOffset));
        output.x12 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(96 + inputOffset));
        output.x13 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(104 + inputOffset));
        output.x14 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(112 + inputOffset));
        output.x15 = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(120 + inputOffset));
    }
    #endregion
}
