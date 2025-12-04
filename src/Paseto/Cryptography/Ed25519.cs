namespace Paseto.Cryptography;

using System;
using Paseto.Internal;
using Internal.Ed25519Ref10;

public static class Ed25519
{
    public static readonly int PublicKeySizeInBytes = 32;
    public static readonly int SignatureSizeInBytes = 64;
    public static readonly int ExpandedPrivateKeySizeInBytes = 32 * 2;
    public static readonly int PrivateKeySeedSizeInBytes = 32;
    public static readonly int SharedKeySizeInBytes = 32;

    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureSizeInBytes)
            throw new ArgumentException($"Signature size must be {SignatureSizeInBytes}", nameof(signature));

        if (publicKey.Length != PublicKeySizeInBytes)
            throw new ArgumentException($"Public key size must be {PublicKeySizeInBytes}", nameof(publicKey));

        return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
    }

    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
    {
        if (signature.Length != SignatureSizeInBytes)
            throw new ArgumentException($"The signature length must be {SignatureSizeInBytes} bytes.");

        if (expandedPrivateKey.Length != ExpandedPrivateKeySizeInBytes)
            throw new ArgumentException($"The expanded private key length must be {ExpandedPrivateKeySizeInBytes} bytes.");

        Ed25519Operations.crypto_sign2(signature, message, expandedPrivateKey);
    }

    public static byte[] Sign(Span<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
    {
        var signature = new byte[SignatureSizeInBytes];
        Sign(signature, message, expandedPrivateKey);
        return signature;
    }

    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> privateKeySeed)
    {
        KeyPairFromSeed(out var publicKey, out var privateKey, privateKeySeed);
        CryptoBytes.Wipe(privateKey);
        return publicKey;
    }

    public static byte[] ExpandedPrivateKeyFromSeed(ReadOnlySpan<byte> privateKeySeed)
    {
        KeyPairFromSeed(out var publicKey, out var privateKey, privateKeySeed);
        CryptoBytes.Wipe(publicKey);
        return privateKey;
    }

    public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, ReadOnlySpan<byte> privateKeySeed)
    {
        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
            throw new ArgumentException("Seed size is invalid", nameof(privateKeySeed));

        var pk = new byte[PublicKeySizeInBytes];
        var sk = new byte[ExpandedPrivateKeySizeInBytes];

        KeyPairFromSeed(pk, sk, privateKeySeed);

        publicKey = pk;
        expandedPrivateKey = sk;
    }

    public static void KeyPairFromSeed(Span<byte> publicKey, Span<byte> expandedPrivateKey, ReadOnlySpan<byte> privateKeySeed)
    {
        if (publicKey.Length != PublicKeySizeInBytes)
            throw new ArgumentException($"The public key length must be {PublicKeySizeInBytes} bytes.");

        if (expandedPrivateKey.Length != ExpandedPrivateKeySizeInBytes)
            throw new ArgumentException($"The expanded private key length must be {ExpandedPrivateKeySizeInBytes} bytes.");

        if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
            throw new ArgumentException($"The private key seed length must be {PrivateKeySeedSizeInBytes} bytes.");

        Ed25519Operations.crypto_sign_keypair(publicKey, 0, expandedPrivateKey, 0, privateKeySeed, 0);
    }
}
