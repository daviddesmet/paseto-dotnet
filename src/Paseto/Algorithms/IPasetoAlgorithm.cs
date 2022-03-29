using System;

namespace Paseto.Algorithms;

public interface IPasetoAlgorithm
{
    /// <summary>
    /// Encrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Encrypt(byte[] payload, byte[] aad, byte[] nonce, byte[] key);

    /// <summary>
    /// Encrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Encrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key);

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    string Decrypt(byte[] payload, byte[] aad, byte[] nonce, byte[] key);

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.Byte[].</returns>
    string Decrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key);

    /// <summary>
    /// Signs the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The secret key.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Sign(byte[] message, byte[] key);

    /// <summary>
    /// Signs the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="key">The secret key.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Sign(ReadOnlySpan<byte> message, ReadOnlyMemory<byte> key);

    /// <summary>
    /// Verifies the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="key">The public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    bool Verify(byte[] message, byte[] signature, byte[] key);

    /// <summary>
    /// Verifies the specified message.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="key">The public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlyMemory<byte> key);

    /// <summary>
    /// Hashes the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Hash(byte[] payload, int size);

    /// <summary>
    /// Hashes the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Hash(ReadOnlySpan<byte> payload, int size);

    /// <summary>
    /// Hashes the specified payload using the specified nonce key.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="nKey">The nonce key.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Hash(byte[] payload, byte[] nKey, int size);

    /// <summary>
    /// Hashes the specified payload using the specified nonce key.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="nKey">The nonce key.</param>
    /// <param name="size">The size.</param>
    /// <returns>System.Byte[].</returns>
    byte[] Hash(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> nKey, int size);
}
