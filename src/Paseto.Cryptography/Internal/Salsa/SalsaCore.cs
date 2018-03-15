namespace Paseto.Cryptography.Internal.Salsa
{
    using System;

    internal static class SalsaCore
    {
        internal static void HSalsa(out Array16<uint> output, ref Array16<uint> input, int rounds)
        {
            InternalAssert.Assert(rounds % 2 == 0, "Number of salsa rounds must be even");

            var doubleRounds = rounds / 2;

            var x0 = input.x0;
            var x1 = input.x1;
            var x2 = input.x2;
            var x3 = input.x3;
            var x4 = input.x4;
            var x5 = input.x5;
            var x6 = input.x6;
            var x7 = input.x7;
            var x8 = input.x8;
            var x9 = input.x9;
            var x10 = input.x10;
            var x11 = input.x11;
            var x12 = input.x12;
            var x13 = input.x13;
            var x14 = input.x14;
            var x15 = input.x15;

            unchecked
            {
                for (var i = 0; i < doubleRounds; i++)
                {
                    uint y;

                    // row 0
                    y = x0 + x12;
                    x4 ^= (y << 7) | (y >> (32 - 7));
                    y = x4 + x0;
                    x8 ^= (y << 9) | (y >> (32 - 9));
                    y = x8 + x4;
                    x12 ^= (y << 13) | (y >> (32 - 13));
                    y = x12 + x8;
                    x0 ^= (y << 18) | (y >> (32 - 18));

                    // row 1
                    y = x5 + x1;
                    x9 ^= (y << 7) | (y >> (32 - 7));
                    y = x9 + x5;
                    x13 ^= (y << 9) | (y >> (32 - 9));
                    y = x13 + x9;
                    x1 ^= (y << 13) | (y >> (32 - 13));
                    y = x1 + x13;
                    x5 ^= (y << 18) | (y >> (32 - 18));

                    // row 2
                    y = x10 + x6;
                    x14 ^= (y << 7) | (y >> (32 - 7));
                    y = x14 + x10;
                    x2 ^= (y << 9) | (y >> (32 - 9));
                    y = x2 + x14;
                    x6 ^= (y << 13) | (y >> (32 - 13));
                    y = x6 + x2;
                    x10 ^= (y << 18) | (y >> (32 - 18));

                    // row 3
                    y = x15 + x11;
                    x3 ^= (y << 7) | (y >> (32 - 7));
                    y = x3 + x15;
                    x7 ^= (y << 9) | (y >> (32 - 9));
                    y = x7 + x3;
                    x11 ^= (y << 13) | (y >> (32 - 13));
                    y = x11 + x7;
                    x15 ^= (y << 18) | (y >> (32 - 18));

                    // column 0
                    y = x0 + x3;
                    x1 ^= (y << 7) | (y >> (32 - 7));
                    y = x1 + x0;
                    x2 ^= (y << 9) | (y >> (32 - 9));
                    y = x2 + x1;
                    x3 ^= (y << 13) | (y >> (32 - 13));
                    y = x3 + x2;
                    x0 ^= (y << 18) | (y >> (32 - 18));

                    // column 1
                    y = x5 + x4;
                    x6 ^= (y << 7) | (y >> (32 - 7));
                    y = x6 + x5;
                    x7 ^= (y << 9) | (y >> (32 - 9));
                    y = x7 + x6;
                    x4 ^= (y << 13) | (y >> (32 - 13));
                    y = x4 + x7;
                    x5 ^= (y << 18) | (y >> (32 - 18));

                    // column 2
                    y = x10 + x9;
                    x11 ^= (y << 7) | (y >> (32 - 7));
                    y = x11 + x10;
                    x8 ^= (y << 9) | (y >> (32 - 9));
                    y = x8 + x11;
                    x9 ^= (y << 13) | (y >> (32 - 13));
                    y = x9 + x8;
                    x10 ^= (y << 18) | (y >> (32 - 18));

                    // column 3
                    y = x15 + x14;
                    x12 ^= (y << 7) | (y >> (32 - 7));
                    y = x12 + x15;
                    x13 ^= (y << 9) | (y >> (32 - 9));
                    y = x13 + x12;
                    x14 ^= (y << 13) | (y >> (32 - 13));
                    y = x14 + x13;
                    x15 ^= (y << 18) | (y >> (32 - 18));
                }
            }

            output.x0 = x0;
            output.x1 = x1;
            output.x2 = x2;
            output.x3 = x3;
            output.x4 = x4;
            output.x5 = x5;
            output.x6 = x6;
            output.x7 = x7;
            output.x8 = x8;
            output.x9 = x9;
            output.x10 = x10;
            output.x11 = x11;
            output.x12 = x12;
            output.x13 = x13;
            output.x14 = x14;
            output.x15 = x15;
        }

        internal static void Salsa(out Array16<UInt32> output, ref Array16<UInt32> input, int rounds)
        {
            HSalsa(out Array16<uint> temp, ref input, rounds);

            unchecked
            {
                output.x0 = temp.x0 + input.x0;
                output.x1 = temp.x1 + input.x1;
                output.x2 = temp.x2 + input.x2;
                output.x3 = temp.x3 + input.x3;
                output.x4 = temp.x4 + input.x4;
                output.x5 = temp.x5 + input.x5;
                output.x6 = temp.x6 + input.x6;
                output.x7 = temp.x7 + input.x7;
                output.x8 = temp.x8 + input.x8;
                output.x9 = temp.x9 + input.x9;
                output.x10 = temp.x10 + input.x10;
                output.x11 = temp.x11 + input.x11;
                output.x12 = temp.x12 + input.x12;
                output.x13 = temp.x13 + input.x13;
                output.x14 = temp.x14 + input.x14;
                output.x15 = temp.x15 + input.x15;
            }
        }
    }
}
