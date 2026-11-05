namespace Paseto.Utils;

using System;

/// <summary>
/// A standards-compliant implementation of web/url-safe base64 encoding and decoding for .NET targets.
/// https://github.com/neosmart/UrlBase64/
/// 
/// Alternative to Microsoft.IdentityModel.Tokens NuGet.
/// </summary>
public class Base64UrlEncoder : IBase64UrlEncoder
{
    private const char OnePadChar = '=';
    private const string TwoPadChar = "==";
    private const char Char62 = '+';
    private const char Char63 = '/';
    private const char UrlChar62 = '-';
    private const char UrlChar63 = '_';

    private static readonly char[] OnePads = { OnePadChar };
    private static readonly char[] InvalidUrlChars = { Char62, Char63, OnePadChar };

    /// <summary>
    /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// The changes make the encoding alphabet file and URL safe.
    /// </summary>
    /// <param name="input">bytes to encode.</param>
    /// <param name="policy">The padding policy.</param>
    /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
    public string Encode(byte[] input, PaddingPolicy policy = PaddingPolicy.Discard) => Encode((ReadOnlySpan<byte>)input, policy);

    /// <summary>
    /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// The changes make the encoding alphabet file and URL safe.
    /// </summary>
    /// <param name="input">bytes to encode.</param>
    /// <param name="policy">The padding policy.</param>
    /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
    public string Encode(ReadOnlySpan<byte> input, PaddingPolicy policy = PaddingPolicy.Discard)
    {
#if NETFRAMEWORK
        // .NET Framework has no ReadOnlySpan<byte> overload of Convert.ToBase64String.
        var encoded = Convert.ToBase64String(input.ToArray()).Replace(Char62, UrlChar62).Replace(Char63, UrlChar63);
#else
        var encoded = Convert.ToBase64String(input).Replace(Char62, UrlChar62).Replace(Char63, UrlChar63);
#endif
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
        // Reject characters that are not part of the base64url alphabet ('+', '/' and the '=' pad),
        // otherwise multiple encodings could map to the same bytes (encoding malleability).
        if (input.IndexOfAny(InvalidUrlChars) != -1)
            throw new FormatException("The input is not a valid base64url encoded string.");

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
