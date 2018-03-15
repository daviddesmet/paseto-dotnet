namespace Paseto.Utils
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    public static class EncodingHelper
    {
        #region Authentication Padding

        /// <summary>
        /// Pre-Authentication Padding.
        /// Multi-part messages (e.g. header, content, footer) are encoded in a specific manner before being passed to the respective cryptographic function.
        /// In local mode, this encoding is applied to the additional associated data (AAD). In remote mode, which is not encrypted, this encoding is applied to the components of the token, with respect to the protocol version being followed.
        /// </summary>
        /// <param name="pieces">The pieces.</param>
        /// <returns>System.Byte[].</returns>
        public static byte[] PreAuthEncode(IReadOnlyList<byte[]> pieces) => BitConverter.GetBytes((long)pieces.Count).Concat(pieces.SelectMany(piece => BitConverter.GetBytes((long)piece.Length).Concat(piece))).ToArray();

        /// <summary>
        /// Pres the authentication encode.
        /// </summary>
        /// <param name="pieces">The pieces.</param>
        /// <returns>System.Byte[].</returns>
        public static byte[] PreAuthEncode(IReadOnlyList<string> pieces) => PreAuthEncode(pieces.Select(GetBytes).ToArray());

        /// <summary>
        /// Pre-Authentication Padding.
        /// </summary>
        /// <param name="pieces">The pieces.</param>
        /// <returns>System.Byte[].</returns>
        [Obsolete("Use new PreAuthEncode method")]
        public static byte[] PAE(IReadOnlyList<byte[]> pieces)
        {
            var output = LE64(pieces.Count);
            foreach (var piece in pieces)
            {
                output = output.Concat(LE64(piece.Length)).ToArray();
                output = output.Concat(piece).ToArray();
            }

            return output;
        }

        /// <summary>
        /// Encodes a 64-bit unsigned integer into a little-endian binary string.
        /// The most significant bit MUST be cleared for interoperability with programming languages that do not have unsigned integer support.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.Byte[].</returns>
        private static byte[] LE64(int input)
        {
            var result = new byte[0];
            for (var i = 0; i < 8; i++)
            {
                //if (i == 7)
                //    input &= 127; // Clear the MSB for interoperability

                result = result.Concat(new[] { (byte)(input & 255) }).ToArray();
                input = input >> 8;
            }

            return result;
        }

        #endregion

        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.Byte[].</returns>
        public static byte[] GetBytes(string input) => Encoding.UTF8.GetBytes(input);

        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.String.</returns>
        public static string GetString(byte[] input) => Encoding.UTF8.GetString(input);

        /// <summary>
        /// Base64 URL safe encoding.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.String.</returns>
        public static string ToBase64Url(string input) => new Base64UrlEncoder().Encode(GetBytes(input));

        /// <summary>
        /// Base64 URL safe encoding.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.String.</returns>
        public static string ToBase64Url(IEnumerable<byte> input) => new Base64UrlEncoder().Encode(input.ToArray());

        /// <summary>
        /// Base64 URL safe decoding.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.Byte[].</returns>
        public static byte[] FromBase64Url(string input) => new Base64UrlEncoder().Decode(input);
    }
}
