namespace Paseto.Utils;

/// <summary>
/// Represents a base64 url encoder/decoder.
/// </summary>
public interface IBase64UrlEncoder
{
    /// <summary>
    /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// The changes make the encoding alphabet file and URL safe.
    /// </summary>
    /// <param name="input">bytes to encode.</param>
    /// <param name="policy">The padding policy.</param>
    /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
    string Encode(byte[] input, PaddingPolicy policy = PaddingPolicy.Discard);

    /// <summary>
    ///  Converts the specified string, which encodes binary data as base-64-url digits, to an equivalent 8-bit unsigned integer array.</summary>
    /// <param name="input">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    byte[] Decode(string input);
}
