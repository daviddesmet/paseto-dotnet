namespace Paseto.Cryptography.Internal
{
    using System;

    /// <summary>
    /// Poly1305 one-time MAC based on RFC 7539.
    ///
    /// This is not an implementation of the MAC interface on purpose and it is not equivalent to HMAC.
    /// The implementation is based on poly1305 implementation by Andrew Moon (https://github.com/floodyberry/poly1305-donna) and released as public domain.
    /// </summary>
    public class Poly1305
    {
        public static int MAC_TAG_SIZE_IN_BYTES = 16;
        public static int MAC_KEY_SIZE_IN_BYTES = 32;

        private Poly1305() { }

        private static long Load32(byte[] buf, int idx)
        {
            //return ByteIntegerConverter.LoadLittleEndian32(buf, idx);
            return ((buf[idx] & 0xff)
                    | ((buf[idx + 1] & 0xff) << 8)
                    | ((buf[idx + 2] & 0xff) << 16)
                    | ((buf[idx + 3] & 0xff) << 24))
                    & 0xffffffffL;
        }

        private static long Load26(byte[] buf, int idx, int shift)
        {
            return (Load32(buf, idx) >> shift) & 0x3ffffff;
        }

        private static void ToByteArray(byte[] output, long num, int idx)
        {
            for (var i = 0; i < 4; i++, num >>= 8)
                output[idx + i] = (byte)(num & 0xff);
        }

        private static void Fill<T>(T[] array, int start, int end, T value)
        {
            if (array == null)
                throw new ArgumentNullException(nameof(array));

            if (start < 0 || start >= end)
                throw new ArgumentOutOfRangeException(nameof(start));

            if (end > array.Length)
                throw new ArgumentOutOfRangeException(nameof(end));

            for (var i = start; i < end; i++)
                array[i] = value;
        }

        private static void CopyBlockSize(byte[] output, byte[] buf, int idx)
        {
            var copyCount = Math.Min(MAC_TAG_SIZE_IN_BYTES, buf.Length - idx);
            Array.Copy(buf, idx, output, 0, copyCount);
            output[copyCount] = 1;
            if (copyCount != MAC_TAG_SIZE_IN_BYTES)
            {
                Fill(output, copyCount + 1, output.Length, (byte)0);
            }
        }

        public static byte[] ComputeMac(byte[] key, byte[] data)
        {
            if (key.Length != MAC_KEY_SIZE_IN_BYTES)
                throw new CryptographyException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

            long h0 = 0;
            long h1 = 0;
            long h2 = 0;
            long h3 = 0;
            long h4 = 0;
            long d0;
            long d1;
            long d2;
            long d3;
            long d4;
            long c;

            // r &= 0xffffffc0ffffffc0ffffffc0fffffff
            long r0 = Load26(key, 0, 0) & 0x3ffffff;
            long r1 = Load26(key, 3, 2) & 0x3ffff03;
            long r2 = Load26(key, 6, 4) & 0x3ffc0ff;
            long r3 = Load26(key, 9, 6) & 0x3f03fff;
            long r4 = Load26(key, 12, 8) & 0x00fffff;

            long s1 = r1 * 5;
            long s2 = r2 * 5;
            long s3 = r3 * 5;
            long s4 = r4 * 5;

            var buf = new byte[MAC_TAG_SIZE_IN_BYTES + 1];
            for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
            {
                CopyBlockSize(buf, data, i);
                h0 += Load26(buf, 0, 0);
                h1 += Load26(buf, 3, 2);
                h2 += Load26(buf, 6, 4);
                h3 += Load26(buf, 9, 6);
                h4 += Load26(buf, 12, 8) | (buf[MAC_TAG_SIZE_IN_BYTES] << 24);

                // d = r * h
                d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
                d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
                d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
                d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
                d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

                // Partial reduction mod 2^130-5, resulting h1 might not be 26bits.
                c = d0 >> 26;
                h0 = d0 & 0x3ffffff;
                d1 += c;
                c = d1 >> 26;
                h1 = d1 & 0x3ffffff;
                d2 += c;
                c = d2 >> 26;
                h2 = d2 & 0x3ffffff;
                d3 += c;
                c = d3 >> 26;
                h3 = d3 & 0x3ffffff;
                d4 += c;
                c = d4 >> 26;
                h4 = d4 & 0x3ffffff;
                h0 += c * 5;
                c = h0 >> 26;
                h0 = h0 & 0x3ffffff;
                h1 += c;
            }
            // Do final reduction mod 2^130-5
            c = h1 >> 26;
            h1 = h1 & 0x3ffffff;
            h2 += c;
            c = h2 >> 26;
            h2 = h2 & 0x3ffffff;
            h3 += c;
            c = h3 >> 26;
            h3 = h3 & 0x3ffffff;
            h4 += c;
            c = h4 >> 26;
            h4 = h4 & 0x3ffffff;
            h0 += c * 5; // c * 5 can be at most 5
            c = h0 >> 26;
            h0 = h0 & 0x3ffffff;
            h1 += c;

            // Compute h - p
            long g0 = h0 + 5;
            c = g0 >> 26;
            g0 &= 0x3ffffff;
            long g1 = h1 + c;
            c = g1 >> 26;
            g1 &= 0x3ffffff;
            long g2 = h2 + c;
            c = g2 >> 26;
            g2 &= 0x3ffffff;
            long g3 = h3 + c;
            c = g3 >> 26;
            g3 &= 0x3ffffff;
            long g4 = h4 + c - (1 << 26);

            // Select h if h < p, or h - p if h >= p
            long mask = g4 >> 63; // mask is either 0 (h >= p) or -1 (h < p)
            h0 &= mask;
            h1 &= mask;
            h2 &= mask;
            h3 &= mask;
            h4 &= mask;
            mask = ~mask;
            h0 |= g0 & mask;
            h1 |= g1 & mask;
            h2 |= g2 & mask;
            h3 |= g3 & mask;
            h4 |= g4 & mask;

            // h = h % (2^128)
            h0 = (h0 | (h1 << 26)) & 0xffffffffL;
            h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffL;
            h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffL;
            h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffL;

            // mac = (h + pad) % (2^128)
            c = h0 + Load32(key, 16);
            h0 = c & 0xffffffffL;
            c = h1 + Load32(key, 20) + (c >> 32);
            h1 = c & 0xffffffffL;
            c = h2 + Load32(key, 24) + (c >> 32);
            h2 = c & 0xffffffffL;
            c = h3 + Load32(key, 28) + (c >> 32);
            h3 = c & 0xffffffffL;

            var mac = new byte[MAC_TAG_SIZE_IN_BYTES];
            ToByteArray(mac, h0, 0);
            ToByteArray(mac, h1, 4);
            ToByteArray(mac, h2, 8);
            ToByteArray(mac, h3, 12);

            return mac;
        }

        public static void VerifyMac(byte[] key, byte[] data, byte[] mac)
        {
            //if (ComputeMac(key, data).SequenceEqual(mac))
            //    throw new CryptographyException("Invalid MAC");

            if (!Equal(ComputeMac(key, data), mac))
                throw new CryptographyException("Invalid MAC");
        }

        private static bool Equal(byte[] left, byte[] right)
        {
            if ((left != null) && (right != null))
            {
                if (left.Length != right.Length)
                    return false;

                for (var i = 0; i < left.Length; i++)
                {
                    if (left[i] != right[i])
                        return false;
                }

                return true;
            }

            return false;
        }
    }
}
