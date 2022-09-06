namespace Paseto.Utils;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Paseto.Extensions;
using System.Buffers.Text;

/// <summary>
/// The Encoding Helper.
/// </summary>
internal static class EncodingHelper
{
    #region Authentication Padding

    /// <summary>
    /// Pre-Authentication Padding.
    /// Multi-part messages (e.g. header, content, footer) are encoded in a specific manner before being passed to the respective cryptographic function.
    /// In local mode, this encoding is applied to the additional associated data (AAD). In remote mode, which is not encrypted, this encoding is applied to the components of the token, with respect to the protocol version being followed.
    ///
    /// See <a href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding">PAE</a>
    /// </summary>
    /// <param name="pieces">The pieces.</param>
    /// <returns>System.Byte[].</returns>
    internal static byte[] PreAuthEncode(params byte[][] pieces)
    {
        var length = (pieces.Length + 1) * 8;
        for (var i = 0; i < pieces.Length; i++)
        {
            length += pieces[i].Length;
        }

        var accumulator = new byte[length];
        SpanExtensions.Copy(LE64(pieces.Length), 0, accumulator, 0, 8);

        var ind = 8;
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            SpanExtensions.Copy(len, 0, accumulator, ind, 8);
            SpanExtensions.Copy(piece, 0, accumulator, ind+8, piece.Length);

            ind += 8 + piece.Length;
        }
        return accumulator;
    }

    /// <summary>
    /// Pre-Authentication Padding.
    /// Multi-part messages (e.g. header, content, footer) are encoded in a specific manner before being passed to the respective cryptographic function.
    /// In local mode, this encoding is applied to the additional associated data (AAD). In remote mode, which is not encrypted, this encoding is applied to the components of the token, with respect to the protocol version being followed.
    ///
    /// See <a href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding">PAE</a>
    /// </summary>
    /// <param name="pieces">The pieces.</param>
    /// <returns>System.Byte[].</returns>
    internal static byte[] PreAuthEncode(IReadOnlyList<byte[]> pieces) => BitConverter.GetBytes((long)pieces.Count).Concat(pieces.SelectMany(piece => BitConverter.GetBytes((long)piece.Length).Concat(piece))).ToArray();

    /// <summary>
    /// Pre-Authentication Padding.
    /// Multi-part messages (e.g. header, content, footer) are encoded in a specific manner before being passed to the respective cryptographic function.
    /// In local mode, this encoding is applied to the additional associated data (AAD). In remote mode, which is not encrypted, this encoding is applied to the components of the token, with respect to the protocol version being followed.
    ///
    /// See <a href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding">PAE</a>
    /// </summary>
    /// <param name="pieces">The pieces.</param>
    /// <returns>System.Byte[].</returns>
    internal static byte[] PreAuthEncode(IReadOnlyList<string> pieces) => PreAuthEncode(pieces.Select(GetBytes).ToArray());

    /// <summary>
    /// Pre-Authentication Padding.
    /// </summary>
    /// <param name="pieces">The pieces.</param>
    /// <returns>System.Byte[].</returns>
    [Obsolete("Use new PreAuthEncode method")]
    internal static byte[] PAE(IReadOnlyList<byte[]> pieces)
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
    /// <param name="n">The input.</param>
    /// <returns>System.Byte[].</returns>
    private static byte[] LE64(int n)
    {
        var up = ~~(n / 0xffffffff);
        var dn = (n % 0xffffffff) - up;

        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(buf[4..], (uint)up);
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)dn);

        return buf.ToArray();
    }

    /// <summary>
    /// Encodes a 64-bit unsigned integer into a little-endian binary string.
    /// The most significant bit MUST be cleared for interoperability with programming languages that do not have unsigned integer support.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.Byte[].</returns>
    private static byte[] LE64Alt(int input)
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
    internal static byte[] GetBytes(string input) => Encoding.UTF8.GetBytes(input);

    /// <summary>
    /// Decodes all the bytes in the specified byte array into a string.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.String.</returns>
    internal static string GetString(byte[] input) => GetString((ReadOnlySpan<byte>)input);

    /// <summary>
    /// Decodes all the bytes in the specified byte array into a string.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.String.</returns>
    internal static string GetString(ReadOnlySpan<byte> input) => Encoding.UTF8.GetString(input);

    /// <summary>
    /// Base64 URL safe encoding.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.String.</returns>
    internal static string ToBase64Url(string input) => new Base64UrlEncoder().Encode(GetBytes(input));

    /// <summary>
    /// Base64 URL safe encoding.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.String.</returns>
    internal static string ToBase64Url(ReadOnlySpan<byte> input) => new Base64UrlEncoder().Encode(input);

    /// <summary>
    /// Base64 URL safe decoding.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns>System.Byte[].</returns>
    internal static byte[] FromBase64Url(string input) => new Base64UrlEncoder().Decode(input);
}
