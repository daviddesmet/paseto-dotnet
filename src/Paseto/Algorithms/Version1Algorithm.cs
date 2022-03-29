namespace Paseto.Algorithms;

using System;
using System.Security.Cryptography;

#if NETSTANDARD2_1 || NETCOREAPP3_1 || NET5_0_OR_GREATER
using Extensions;
#endif
using static Utils.EncodingHelper;

/// <summary>
/// Paseto Version 2 Algorithm.
/// </summary>
/// <seealso cref="Paseto.Algorithms.IPasetoAlgorithm" />
internal sealed class Version1Algorithm : IPasetoAlgorithm
{
    /// <summary>
    /// Encrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Encrypt(byte[] payload, byte[] aad, byte[] nonce, byte[] key) => Encrypt((ReadOnlySpan<byte>)payload, (ReadOnlySpan<byte>)aad, (ReadOnlySpan<byte>)nonce, (ReadOnlyMemory<byte>)key);

    /// <summary>
    /// Encrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Encrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key) => throw new NotSupportedException("The Local Purpose is not supported in the Version 1 Protocol");

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="nonce">The nonce.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(byte[] payload, byte[] aad, byte[] nonce, byte[] key) => Decrypt((ReadOnlySpan<byte>)payload, (ReadOnlySpan<byte>)aad, (ReadOnlySpan<byte>)nonce, (ReadOnlyMemory<byte>)key);

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="nonce">The nonce.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key) => throw new NotSupportedException("The Local Purpose is not supported in the Version 1 Protocol");

    /// <summary>
    /// Signs the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The secret key.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Sign(byte[] message, byte[] key) => Sign((ReadOnlySpan<byte>)message, (ReadOnlyMemory<byte>)key);

    /// <summary>
    /// Signs the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The secret key.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Sign(ReadOnlySpan<byte> message, ReadOnlyMemory<byte> key)
    {
#if NETSTANDARD2_1 || NETCOREAPP3_1 || NET5_0_OR_GREATER
        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(key.Span));

        return rsa.SignData(message.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
#elif NET46 || NET47 || NET48
        using (var rsa = new RSACng())
        {
            //rsa.KeySize = 2048; // Default
            rsa.FromXmlString(GetString(key.Span));

            return rsa.SignData(message.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }
#endif
    }

    /// <summary>
    /// Verifies the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="key">The public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    public bool Verify(byte[] message, byte[] signature, byte[] key) => Verify((ReadOnlySpan<byte>)message, (ReadOnlySpan<byte>)signature, (ReadOnlyMemory<byte>)key);

    /// <summary>
    /// Verifies the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="key">The public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlyMemory<byte> key)
    {
#if NETSTANDARD2_1 || NETCOREAPP3_1 || NET5_0_OR_GREATER
        // NOTE: Not Supported in Linux until 2.1
        // Enable RSA-OAEP(SHA-2) and RSA-PSS on Unix systems #27394
        // https://github.com/dotnet/corefx/pull/27394
        // https://github.com/dotnet/corefx/issues/2522

        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(key.Span));

        return rsa.VerifyData(message, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
#elif NET46 || NET47 || NET48
        using (var rsa = new RSACng())
        {
            //rsa.KeySize = 2048; // Default
            rsa.FromXmlString(GetString(key.Span));

            return rsa.VerifyData(message.ToArray(), signature.ToArray(), HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }
#endif
    }

    /// <summary>
    /// Hashes the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Hash(byte[] payload, int size) => Hash((ReadOnlySpan<byte>)payload, size);

    /// <summary>
    /// Hashes the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Hash(ReadOnlySpan<byte> payload, int size) => throw new NotImplementedException();

    /// <summary>
    /// Hashes the specified payload using the specified nonce key.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="nKey">The nonce key.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Hash(byte[] payload, byte[] nKey, int size) => Hash((ReadOnlySpan<byte>)payload, (ReadOnlySpan<byte>)nKey, size);

    /// <summary>
    /// Hashes the specified payload using the specified nonce key.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="nKey">The nonce key.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    public byte[] Hash(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> nKey, int size) => throw new NotImplementedException();
}
