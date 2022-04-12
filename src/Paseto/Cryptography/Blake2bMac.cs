namespace Paseto.Cryptography;

using System;
using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// An implementation of Blake2b HMAC per RFC-7693
/// </summary>
public class Blake2bMac : HMAC
{
    public const int HASH_SIZE_MIN = 8;
    public const int HASH_SIZE_MAX = 512;
    public const int KEY_SIZE_MAX = 64;

    private readonly int _hashSize;
    private readonly Func<Blake2bBase> _createImpl;
    private Blake2bBase _implementation;

    /// <summary>
    /// Construct an HMACBlake2B without a key
    /// </summary>
    /// <param name="hashSize">the hash size in bits</param>
    public Blake2bMac(int hashSize)
    {
        HashName = "Blake2bMac";

        if ((hashSize % HASH_SIZE_MIN) > 0)
            throw new ArgumentException("Hash size must be byte aligned", nameof(hashSize));

        if (hashSize < HASH_SIZE_MIN || hashSize > HASH_SIZE_MAX)
            throw new ArgumentException($"Hash size must be between {HASH_SIZE_MIN} and {HASH_SIZE_MAX}", nameof(hashSize));

        _hashSize = hashSize;
        _createImpl = CreateImplementation;
        Key = Array.Empty<byte>();
    }

    /// <summary>
    /// Construct an HMACBlake2B
    /// </summary>
    /// <param name="keyData">The key for the HMAC</param>
    /// <param name="hashSize">The hash size in bits</param>
    public Blake2bMac(byte[] keyData, int hashSize) : this(hashSize)
    {
        if (keyData is null)
            keyData = Array.Empty<byte>();

        if (keyData.Length > KEY_SIZE_MAX)
            throw new ArgumentException($"Key needs to be between 0 and {KEY_SIZE_MAX} bytes", nameof(keyData));

        Key = keyData;
    }

    internal Blake2bMac(byte[] keyData, int hashSize, Func<Blake2bBase> baseCreator) : this(keyData, hashSize) => _createImpl = baseCreator;

    /// <summary>
    /// Implementation of HashSize <seealso cref="System.Security.Cryptography.HashAlgorithm"/>
    /// </summary>
    /// <returns>The hash</returns>
    public override int HashSize => _hashSize;

    /// <summary>
    /// Overridden key to enforce size
    /// </summary>
    public override byte[] Key
    {
        get => base.Key;
        set => base.Key = value;
    }

    /// <summary>
    /// Implementation of Initialize - initializes the HMAC buffer
    /// </summary>
    public override void Initialize()
    {
        _implementation = _createImpl();
        _implementation.Initialize(Key);
    }

    /// <summary>
    /// Implementation of HashCore
    /// </summary>
    /// <param name="data">The data to hash</param>
    /// <param name="offset">The offset to start hashing from</param>
    /// <param name="size">The amount of data in the hash to consume</param>
    protected override void HashCore(byte[] data, int offset, int size)
    {
        if (_implementation is null)
            Initialize();

        _implementation.Update(data, offset, size);
    }

    /// <summary>
    /// Finish hashing and return the final hash
    /// </summary>
    /// <returns>The final hash from HashCore</returns>
    protected override byte[] HashFinal() => _implementation.Final();

    private Blake2bBase CreateImplementation()
    {
        if (Vector.IsHardwareAccelerated)
            return new Blake2bSimd(_hashSize / 8);

        return new Blake2bNormal(_hashSize / 8);
    }
}
