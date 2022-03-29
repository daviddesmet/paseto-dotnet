namespace Paseto.Algorithms;

using System;
using System.Security.Cryptography;

using NaCl.Core;
using Paseto.Cryptography;
using Paseto.Cryptography.Internal;
using static Utils.EncodingHelper;

/// <summary>
/// Paseto Version 2 Algorithm.
/// </summary>
/// <seealso cref="Paseto.Algorithms.IPasetoAlgorithm" />
internal sealed class Version2Algorithm : IPasetoAlgorithm
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
    public byte[] Encrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key)
    {
        // Using NaCl.Core Cryptography library
        var algo = new XChaCha20Poly1305(key);

        var ciphertext = new byte[payload.Length];
        var tag = new byte[16];

        algo.Encrypt(nonce, payload, ciphertext, tag, aad);
        return CryptoBytes.Combine(ciphertext, tag);

        /*
         * Sodium
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        return SecretAead.Encrypt(payload, nonce, key, aad);
        */

        /*
         * NSec
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        var algo = new NSec.Cryptography.XChaCha20Poly1305();
        using (var k = NSec.Cryptography.Key.Import(algo, key.Span, NSec.Cryptography.KeyBlobFormat.RawSymmetricKey))
            return algo.Encrypt(k, nonce, aad, payload);
        */
    }

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(byte[] payload, byte[] aad, byte[] nonce, byte[] key) => Decrypt((ReadOnlySpan<byte>)payload, (ReadOnlySpan<byte>)aad, (ReadOnlySpan<byte>)nonce, (ReadOnlyMemory<byte>)key);

    /// <summary>
    /// Decrypts the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="aad">The additional associated data.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="key">The symmetric key.</param>
    /// <returns>System.String.</returns>
    public string Decrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlyMemory<byte> key)
    {
        // Using NaCl.Core Cryptography library
        var algo = new XChaCha20Poly1305(key);

        var len = payload.Length - 16;
        var plainText = new byte[len];
        var tag = payload[len..];

        algo.Decrypt(nonce, payload[..len], tag, plainText, aad);
        return GetString(plainText);

        /*
         * Sodium
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        return GetString(SecretAead.Decrypt(payload, nonce, key, associatedData));
        */

        /*
         * NSec
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        var algo = new XChaCha20Poly1305();
        using (var k = Key.Import(algo, key, KeyBlobFormat.RawSymmetricKey))
            return GetString(algo.Decrypt(k, new Nonce(nonce, 0), aad, payload));
        */
    }

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
        // Using Paseto Cryptography library
#pragma warning disable IDE0022 // Use expression body for methods
        return Ed25519.Sign(message.ToArray(), key.ToArray());
#pragma warning restore IDE0022 // Use expression body for methods

        /*
         * Using NSec library
         *
        var algo = new Ed25519();
        using (var k = Key.Import(algo, key, KeyBlobFormat.RawPrivateKey))
        {
            return algo.Sign(k, message);
        }
        */

        // Using Sodium Core library
        //return PublicKeyAuth.SignDetached(message, key);
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
        // Using Paseto Cryptography library
#pragma warning disable IDE0022 // Use expression body for methods
        return Ed25519.Verify(signature.ToArray(), message.ToArray(), key.ToArray());
#pragma warning restore IDE0022 // Use expression body for methods

        /*
         * Using NSec library
         *
        var algo = new Ed25519();
        var publicKey = PublicKey.Import(algo, key, KeyBlobFormat.RawPublicKey);
        algo.Verify(publicKey, message, signature);
        */

        // Using Sodium Core library
        //return PublicKeyAuth.VerifyDetached(signature, message, key);
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
    public byte[] Hash(ReadOnlySpan<byte> payload, int size)
    {
        var nKey = new byte[size];

        RandomNumberGenerator.Create().GetBytes(nKey);

        // Using Paseto Cryptography library
        var hash = new Blake2bMac(nKey, size * 8);
        return hash.ComputeHash(payload.ToArray());

        /*
         * Using NSec library
         *
        var algo = new Blake2bMac();
        using (var key = Key.Import(algo, nKey, KeyBlobFormat.RawSymmetricKey))
            return algo.Mac(key, payload, size);
        */

        // Using Sodium Core library
        //var hash = new GenericHash.GenericHashAlgorithm(nKey, size);
        //return hash.ComputeHash(GetBytes(payload));
    }

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
    public byte[] Hash(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> nKey, int size)
    {
        // Using Paseto Cryptography library
        /*
        using var hash = new Blake2B(size * 8);
        hash.Key = nKey.ToArray(); // Keyed hashing, hash hmac
        return hash.ComputeHash(payload.ToArray());
        */

        var hash = new Blake2bMac(nKey.ToArray(), size * 8);
        return hash.ComputeHash(payload.ToArray());

        /*
         * Using NSec library
         *
        var algo = new NSec.Cryptography.Blake2bMac(size, size);
        using (var key = NSec.Cryptography.Key.Import(algo, nKey, NSec.Cryptography.KeyBlobFormat.RawSymmetricKey))
            return algo.Mac(key, payload);
        */

        // Using Sodium Core library
        //var hash = new GenericHash.GenericHashAlgorithm(nKey, size);
        //return hash.ComputeHash(GetBytes(payload));
    }
}
