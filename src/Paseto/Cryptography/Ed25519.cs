﻿namespace Paseto.Cryptography;

using System;
using NaCl.Core.Internal;
using Paseto.Cryptography.Internal.Ed25519Ref10;

public static class Ed25519
{
    public static readonly int PublicKeySizeInBytes = 32;
    public static readonly int SignatureSizeInBytes = 64;
    public static readonly int ExpandedPrivateKeySizeInBytes = 32 * 2;
    public static readonly int PrivateKeySeedSizeInBytes = 32;
    public static readonly int SharedKeySizeInBytes = 32;

    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature == default)
            throw new ArgumentNullException(nameof(signature));

        if (message == default)
            throw new ArgumentNullException(nameof(message));

        if (publicKey == default)
            throw new ArgumentNullException(nameof(publicKey));

        if (signature.Length != SignatureSizeInBytes)
            throw new ArgumentException(string.Format("Signature size must be {0}", SignatureSizeInBytes), "signature.Length");

        if (publicKey.Length != PublicKeySizeInBytes)
            throw new ArgumentException(string.Format("Public key size must be {0}", PublicKeySizeInBytes), "publicKey.Length");

        return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
    }

    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
    {
        if (signature == default)
            throw new ArgumentNullException("signature.Array");

        if (signature.Length != SignatureSizeInBytes)
            throw new ArgumentException("signature.Length");

        if (expandedPrivateKey == default)
            throw new ArgumentNullException("expandedPrivateKey.Array");

        if (expandedPrivateKey.Length != ExpandedPrivateKeySizeInBytes)
            throw new ArgumentException("expandedPrivateKey.Length");

        if (message == default)
            throw new ArgumentNullException("message.Array");

        Ed25519Operations.crypto_sign2(signature, message, expandedPrivateKey);
    }

    public static byte[] Sign(Span<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
    {
        var signature = new byte[SignatureSizeInBytes];
        Sign(signature, message, expandedPrivateKey);
        return signature;
    }

    public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
    {
        KeyPairFromSeed(out byte[] publicKey, out byte[] privateKey, privateKeySeed);
        CryptoBytes.Wipe(privateKey);
        return publicKey;
    }

    public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
    {
        KeyPairFromSeed(out byte[] publicKey, out byte[] privateKey, privateKeySeed);
        CryptoBytes.Wipe(publicKey);
        return privateKey;
    }

    public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
    {
        if (privateKeySeed == null)
            throw new ArgumentNullException(nameof(privateKeySeed));

        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
            throw new ArgumentException("Seed size is invalid", nameof(privateKeySeed));

        var pk = new byte[PublicKeySizeInBytes];
        var sk = new byte[ExpandedPrivateKeySizeInBytes];

        Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);

        publicKey = pk;
        expandedPrivateKey = sk;
    }

    public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
    {
        if (publicKey.Array == null)
            throw new ArgumentNullException("publicKey.Array");

        if (expandedPrivateKey.Array == null)
            throw new ArgumentNullException("expandedPrivateKey.Array");

        if (privateKeySeed.Array == null)
            throw new ArgumentNullException("privateKeySeed.Array");

        if (publicKey.Count != PublicKeySizeInBytes)
            throw new ArgumentException("publicKey.Count");

        if (expandedPrivateKey.Count != ExpandedPrivateKeySizeInBytes)
            throw new ArgumentException("expandedPrivateKey.Count");

        if (privateKeySeed.Count != PrivateKeySeedSizeInBytes)
            throw new ArgumentException("privateKeySeed.Count");

        Ed25519Operations.crypto_sign_keypair(publicKey.Array, publicKey.Offset, expandedPrivateKey.Array, expandedPrivateKey.Offset, privateKeySeed.Array, privateKeySeed.Offset);
    }
}
