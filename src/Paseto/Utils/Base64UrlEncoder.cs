namespace Paseto.Utils
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// A standards-compliant implementation of web/url-safe base64 encoding and decoding for .NET targets.
    /// https://github.com/neosmart/UrlBase64/
    /// 
    /// Alternative to Microsoft.IdentityModel.Tokens NuGet.
    /// </summary>
    public class Base64UrlEncoder : IBase64UrlEncoder
    {
        private static char OnePadChar = '=';
        private static string TwoPadChar = "==";
        private static char Char62 = '+';
        private static char Char63 = '/';
        private static char UrlChar62 = '-';
        private static char UrlChar63 = '_';

        private static readonly char[] OnePads = { OnePadChar };

        /// <summary>
        /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
        /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
        /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
        /// The changes make the encoding alphabet file and URL safe.
        /// </summary>
        /// <param name="input">bytes to encode.</param>
        /// <param name="policy">The padding policy.</param>
        /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
        public string Encode(byte[] input, PaddingPolicy policy = PaddingPolicy.Discard)
        {
            var encoded = Convert.ToBase64String(input).Replace(Char62, UrlChar62).Replace(Char63, UrlChar63);
            if (policy == PaddingPolicy.Discard)
                encoded = encoded.TrimEnd(OnePads);

            return encoded;
        }

        /// <summary>
        ///  Converts the specified string, which encodes binary data as base-64-url digits, to an equivalent 8-bit unsigned integer array.</summary>
        /// <param name="input">base64Url encoded string.</param>
        /// <returns>UTF8 bytes.</returns>
        public byte[] Decode(string input)
        {
            switch (input.Length % 4)
            {
                case 2:
                    input += TwoPadChar;
                    break;
                case 3:
                    input += OnePadChar;
                    break;
            }

            //return Convert.FromBase64String(encoded.PadRight((encoded.Length % 4) == 0 ? 0 : (encoded.Length + 4 - (encoded.Length % 4)), OnePadChar).Replace(UrlChar62, Char62).Replace(UrlChar63, Char63));
            return Convert.FromBase64String(input.Replace(UrlChar62, Char62).Replace(UrlChar63, Char63));
        }
    }
}
