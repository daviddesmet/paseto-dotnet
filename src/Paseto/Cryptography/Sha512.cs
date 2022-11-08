namespace Paseto.Cryptography;

using System;
using System.Buffers.Binary;
using Paseto.Cryptography.Internal;
using Paseto.Extensions;

public class Sha512
{
    private Array8<ulong> _state;
    private readonly byte[] _buffer;
    private ulong _totalBytes;
    public const int BlockSize = 128;
    private static readonly byte[] _padding = new byte[] { 0x80 };

    public Sha512()
    {
        _buffer = new byte[BlockSize]; // TODO: remove allocation
        Init();
    }

    public void Init()
    {
        Sha512Internal.Sha512Init(out _state);
        _totalBytes = 0;
    }

    public void Update(ReadOnlySpan<byte> data, int offset, int count)
    {
        if (data == default)
            throw new ArgumentNullException(nameof(data));

        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));

        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        if (data.Length - offset < count)
            throw new ArgumentException("Requires offset + count <= data.Length");

        Update(data.Slice(offset, count));
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        if (data == default)
            throw new ArgumentNullException(nameof(data));

        var count = data.Length;
        var offset = 0;

        Array16<ulong> block;
        var bytesInBuffer = (int)_totalBytes & (BlockSize - 1);
        _totalBytes += (uint)count;

        if (_totalBytes >= ulong.MaxValue / 8)
            throw new InvalidOperationException("Too much data");

        // Fill existing buffer
        if (bytesInBuffer != 0)
        {
            var toCopy = Math.Min(BlockSize - bytesInBuffer, count);
            SpanExtensions.Copy(data, offset, _buffer, bytesInBuffer, toCopy);
            offset += toCopy;
            count -= toCopy;
            bytesInBuffer += toCopy;
            if (bytesInBuffer == BlockSize)
            {
                ByteIntegerConverter.Array16LoadBigEndian64(out block, _buffer, 0);
                Sha512Internal.Core(out _state, ref _state, ref block);
                Array.Clear(_buffer, 0, _buffer.Length);
                bytesInBuffer = 0;
            }
        }

        // Hash complete blocks without copying
        while (count >= BlockSize)
        {
            ByteIntegerConverter.Array16LoadBigEndian64(out block, data, offset);
            Sha512Internal.Core(out _state, ref _state, ref block);
            offset += BlockSize;
            count -= BlockSize;
        }

        // Copy remainder into buffer
        if (count > 0)
            SpanExtensions.Copy(data, offset, _buffer, bytesInBuffer, count);
    }

    public void Finish(Span<byte> output)
    {
        if (output == default)
            throw new ArgumentNullException(nameof(output));

        if (output.Length != 64)
            throw new ArgumentException("output.Length must be 64");

        Update(_padding, 0, _padding.Length);
        ByteIntegerConverter.Array16LoadBigEndian64(out Array16<ulong> block, _buffer, 0);
        Array.Clear(_buffer, 0, _buffer.Length);
        var bytesInBuffer = (int)_totalBytes & (BlockSize - 1);
        if (bytesInBuffer > BlockSize - 16)
        {
            Sha512Internal.Core(out _state, ref _state, ref block);
            block = default(Array16<ulong>);
        }
        block.x15 = (_totalBytes - 1) * 8;
        Sha512Internal.Core(out _state, ref _state, ref block);

        BinaryPrimitives.WriteUInt64BigEndian(output, _state.x0);
        BinaryPrimitives.WriteUInt64BigEndian(output[8..], _state.x1);
        BinaryPrimitives.WriteUInt64BigEndian(output[16..], _state.x2);
        BinaryPrimitives.WriteUInt64BigEndian(output[24..], _state.x3);
        BinaryPrimitives.WriteUInt64BigEndian(output[32..], _state.x4);
        BinaryPrimitives.WriteUInt64BigEndian(output[40..], _state.x5);
        BinaryPrimitives.WriteUInt64BigEndian(output[48..], _state.x6);
        BinaryPrimitives.WriteUInt64BigEndian(output[56..], _state.x7);
        _state = default(Array8<ulong>);
    }

    public byte[] Finish()
    {
        var result = new byte[64];
        Finish(result);
        return result;
    }

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var hasher = new Sha512();
        hasher.Update(data);
        return hasher.Finish();
    }

    public static byte[] Hash(ReadOnlySpan<byte> data, int offset, int count) => Hash(data.Slice(offset, count));
}