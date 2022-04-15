namespace Paseto.Cryptography;

using System;

internal abstract class Blake2bBase
{
    private readonly uint _hashSize;
    private readonly ulong[] _h = new ulong[8];
    private readonly ulong[] _t = new ulong[2];
    private readonly byte[] _b = new byte[128];
    private int _c;

    public Blake2bBase(int hashBytes) => _hashSize = (uint)hashBytes;

    public int ByteSize => (int)_hashSize;

    protected ulong[] Hash => _h;

    protected ulong TotalSegmentsLow => _t[0];

    protected ulong TotalSegmentsHigh => _t[1];

    protected byte[] DataBuffer => _b;

    public void Initialize(byte[] key)
    {
        if ((key?.Length ?? 0) > _b.Length)
            throw new ArgumentException($"Blake2 key size is too large. Max size is {_b.Length} bytes", nameof(key));

        Array.Copy(Blake2Constants.IV, _h, 8);
        _h[0] ^= 0x01010000UL ^ (((ulong)(key?.Length ?? 0)) << 8) ^ _hashSize;

        // Start with the key
        if (key?.Length > 0)
        {
            Array.Copy(key, _b, key.Length);
            Update(_b, 0, _b.Length);
        }
    }

    public void Update(byte[] data, int offset, int size)
    {
        while (size > 0)
        {
            if (_c == 128)
            {
                _t[0] += (ulong)_c;
                if (_t[0] < (ulong)_c)
                    ++_t[1];

                // We filled our buffer
                Compress(false);
                _c = 0;
            }

            var nextChunk = Math.Min(size, 128 - _c);

            // copy the next batch of data
            Array.Copy(data, offset, _b, _c, nextChunk);
            _c += nextChunk;
            offset += nextChunk;

            size -= nextChunk;
        }
    }

    public byte[] Final()
    {
        _t[0] += (ulong)_c;
        if (_t[0] < (ulong)_c)
            ++_t[1];

        while (_c < 128)
            _b[_c++] = 0;
        _c = 0;

        Compress(true);
        var hashByteSize = _hashSize;
        var result = new byte[hashByteSize];
        for (var i = 0; i < hashByteSize; ++i)
            result[i] = (byte)((_h[i >> 3] >> (8 * (i & 7))) & 0xff);

        return result;
    }

    public abstract void Compress(bool isFinal);
}
