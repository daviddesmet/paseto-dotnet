namespace Paseto.Cryptography.Internal
{
    // Loops? Arrays? Never heard of that stuff
    // Library avoids unnecessary heap allocations and unsafe code
    // so this ugly code becomes necessary :(
    internal static class ByteIntegerConverter
    {
        #region Individual

        /// <summary>
        /// Loads 4 bytes of the input buffer into an unsigned 32-bit integer, beginning at the input offset.
        /// </summary>
        /// <param name="buf">The input buffer.</param>
        /// <param name="offset">The input offset.</param>
        /// <returns>System.UInt32.</returns>
        public static uint LoadLittleEndian32(byte[] buf, int offset)
        {
            return
                (uint)(buf[offset + 0])
                | (((uint)(buf[offset + 1])) << 8)
                | (((uint)(buf[offset + 2])) << 16)
                | (((uint)(buf[offset + 3])) << 24);
        }

        /// <summary>
        /// Stores the value into the buffer.
        /// The value will be split into 4 bytes and put into four sequential places in the output buffer, starting at the specified offset.
        /// </summary>
        /// <param name="buf">The output buffer.</param>
        /// <param name="offset">The output offset.</param>
        /// <param name="value">The input value.</param>
        public static void StoreLittleEndian32(byte[] buf, int offset, uint value)
        {
            buf[offset + 0] = unchecked((byte)value);
            buf[offset + 1] = unchecked((byte)(value >> 8));
            buf[offset + 2] = unchecked((byte)(value >> 16));
            buf[offset + 3] = unchecked((byte)(value >> 24));
        }

        public static ulong LoadBigEndian64(byte[] buf, int offset)
        {
            return
                (ulong)(buf[offset + 7])
                | (((ulong)(buf[offset + 6])) << 8)
                | (((ulong)(buf[offset + 5])) << 16)
                | (((ulong)(buf[offset + 4])) << 24)
                | (((ulong)(buf[offset + 3])) << 32)
                | (((ulong)(buf[offset + 2])) << 40)
                | (((ulong)(buf[offset + 1])) << 48)
                | (((ulong)(buf[offset + 0])) << 56);
        }

        public static void StoreBigEndian64(byte[] buf, int offset, ulong value)
        {
            buf[offset + 7] = unchecked((byte)value);
            buf[offset + 6] = unchecked((byte)(value >> 8));
            buf[offset + 5] = unchecked((byte)(value >> 16));
            buf[offset + 4] = unchecked((byte)(value >> 24));
            buf[offset + 3] = unchecked((byte)(value >> 32));
            buf[offset + 2] = unchecked((byte)(value >> 40));
            buf[offset + 1] = unchecked((byte)(value >> 48));
            buf[offset + 0] = unchecked((byte)(value >> 56));
        }

        /*public static void XorLittleEndian32(byte[] buf, int offset, uint value)
        {
            buf[offset + 0] ^= (byte)value;
            buf[offset + 1] ^= (byte)(value >> 8);
            buf[offset + 2] ^= (byte)(value >> 16);
            buf[offset + 3] ^= (byte)(value >> 24);
        }*/

        /*public static void XorLittleEndian32(byte[] output, int outputOffset, byte[] input, int inputOffset, uint value)
        {
            output[outputOffset + 0] = (byte)(input[inputOffset + 0] ^ value);
            output[outputOffset + 1] = (byte)(input[inputOffset + 1] ^ (value >> 8));
            output[outputOffset + 2] = (byte)(input[inputOffset + 2] ^ (value >> 16));
            output[outputOffset + 3] = (byte)(input[inputOffset + 3] ^ (value >> 24));
        }*/

        #endregion

        #region Array8
        
        public static void Array8LoadLittleEndian32(out Array8<uint> output, byte[] input, int inputOffset)
        {
            output.x0 = LoadLittleEndian32(input, inputOffset + 0);
            output.x1 = LoadLittleEndian32(input, inputOffset + 4);
            output.x2 = LoadLittleEndian32(input, inputOffset + 8);
            output.x3 = LoadLittleEndian32(input, inputOffset + 12);
            output.x4 = LoadLittleEndian32(input, inputOffset + 16);
            output.x5 = LoadLittleEndian32(input, inputOffset + 20);
            output.x6 = LoadLittleEndian32(input, inputOffset + 24);
            output.x7 = LoadLittleEndian32(input, inputOffset + 28);
        }

        public static void Array8StoreLittleEndian32(byte[] output, int outputOffset, ref Array8<uint> input)
        {
            StoreLittleEndian32(output, outputOffset + 0, input.x0);
            StoreLittleEndian32(output, outputOffset + 4, input.x1);
            StoreLittleEndian32(output, outputOffset + 8, input.x2);
            StoreLittleEndian32(output, outputOffset + 12, input.x3);
            StoreLittleEndian32(output, outputOffset + 16, input.x4);
            StoreLittleEndian32(output, outputOffset + 20, input.x5);
            StoreLittleEndian32(output, outputOffset + 24, input.x6);
            StoreLittleEndian32(output, outputOffset + 28, input.x7);
        }

        public static void Array8StoreLittleEndian32(byte[] output, int outputOffset, ref Array16<uint> input)
        {
            StoreLittleEndian32(output, outputOffset + 0, input.x0);
            StoreLittleEndian32(output, outputOffset + 4, input.x1);
            StoreLittleEndian32(output, outputOffset + 8, input.x2);
            StoreLittleEndian32(output, outputOffset + 12, input.x3);
            StoreLittleEndian32(output, outputOffset + 16, input.x4);
            StoreLittleEndian32(output, outputOffset + 20, input.x5);
            StoreLittleEndian32(output, outputOffset + 24, input.x6);
            StoreLittleEndian32(output, outputOffset + 28, input.x7);
        }

        #endregion

        #region Array16

        public static void Array16LoadBigEndian64(out Array16<ulong> output, byte[] input, int inputOffset)
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

        // TODO: Only used in tests. Remove?
        public static void Array16LoadLittleEndian32(out Array16<uint> output, byte[] input, int inputOffset)
        {
            output.x0 = LoadLittleEndian32(input, inputOffset + 0);
            output.x1 = LoadLittleEndian32(input, inputOffset + 4);
            output.x2 = LoadLittleEndian32(input, inputOffset + 8);
            output.x3 = LoadLittleEndian32(input, inputOffset + 12);
            output.x4 = LoadLittleEndian32(input, inputOffset + 16);
            output.x5 = LoadLittleEndian32(input, inputOffset + 20);
            output.x6 = LoadLittleEndian32(input, inputOffset + 24);
            output.x7 = LoadLittleEndian32(input, inputOffset + 28);
            output.x8 = LoadLittleEndian32(input, inputOffset + 32);
            output.x9 = LoadLittleEndian32(input, inputOffset + 36);
            output.x10 = LoadLittleEndian32(input, inputOffset + 40);
            output.x11 = LoadLittleEndian32(input, inputOffset + 44);
            output.x12 = LoadLittleEndian32(input, inputOffset + 48);
            output.x13 = LoadLittleEndian32(input, inputOffset + 52);
            output.x14 = LoadLittleEndian32(input, inputOffset + 56);
            output.x15 = LoadLittleEndian32(input, inputOffset + 60);
        }

        public static void Array16StoreLittleEndian32(byte[] output, int outputOffset, ref Array16<uint> input)
        {
            StoreLittleEndian32(output, outputOffset + 0, input.x0);
            StoreLittleEndian32(output, outputOffset + 4, input.x1);
            StoreLittleEndian32(output, outputOffset + 8, input.x2);
            StoreLittleEndian32(output, outputOffset + 12, input.x3);
            StoreLittleEndian32(output, outputOffset + 16, input.x4);
            StoreLittleEndian32(output, outputOffset + 20, input.x5);
            StoreLittleEndian32(output, outputOffset + 24, input.x6);
            StoreLittleEndian32(output, outputOffset + 28, input.x7);
            StoreLittleEndian32(output, outputOffset + 32, input.x8);
            StoreLittleEndian32(output, outputOffset + 36, input.x9);
            StoreLittleEndian32(output, outputOffset + 40, input.x10);
            StoreLittleEndian32(output, outputOffset + 44, input.x11);
            StoreLittleEndian32(output, outputOffset + 48, input.x12);
            StoreLittleEndian32(output, outputOffset + 52, input.x13);
            StoreLittleEndian32(output, outputOffset + 56, input.x14);
            StoreLittleEndian32(output, outputOffset + 60, input.x15);
        }

        public static void Array16Copy(out Array16<uint> output, Array16<uint> input)
        {
            output.x0 = input.x0;
            output.x1 = input.x1;
            output.x2 = input.x2;
            output.x3 = input.x3;
            output.x4 = input.x4;
            output.x5 = input.x5;
            output.x6 = input.x6;
            output.x7 = input.x7;
            output.x8 = input.x8;
            output.x9 = input.x9;
            output.x10 = input.x10;
            output.x11 = input.x11;
            output.x12 = input.x12;
            output.x13 = input.x13;
            output.x14 = input.x14;
            output.x15 = input.x15;
        }

        public static T[] Array16ToArray<T>(Array16<T> input)
        {
            var output = new T[16];
            output[0] = input.x0;
            output[1] = input.x1;
            output[2] = input.x2;
            output[3] = input.x3;
            output[4] = input.x4;
            output[5] = input.x5;
            output[6] = input.x6;
            output[7] = input.x7;
            output[8] = input.x8;
            output[9] = input.x9;
            output[10] = input.x10;
            output[11] = input.x11;
            output[12] = input.x12;
            output[13] = input.x13;
            output[14] = input.x14;
            output[15] = input.x15;
            return output;
        }

        #endregion
    }
}
