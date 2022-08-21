﻿namespace Paseto.Cryptography;

using System;
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

    public void Update(ArraySegment<byte> data)
    {
        if (data.Array == null)
            throw new ArgumentNullException("data.Array");

        Update(data.Array, data.Offset, data.Count);
    }

    public void Update(Span<byte> data, int offset, int count)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));

        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count));

        if (data.Length - offset < count)
            throw new ArgumentException("Requires offset + count <= data.Length");

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
            ByteIntegerConverterExtensions.Array16LoadBigEndian64(out block, data, offset);
            Sha512Internal.Core(out _state, ref _state, ref block);
            offset += BlockSize;
            count -= BlockSize;
        }

        // Copy remainder into buffer
        if (count > 0)

            /* Unmerged change from project 'Paseto (net6.0)'
            Before:
                        CryptoBytesExtensions.SpanCopy(data, offset, _buffer, bytesInBuffer, count);
            After:
                        Extensions.SpanExtensions.SpanCopy(data, offset, _buffer, bytesInBuffer, count);
            */
            SpanExtensions.Copy(data, offset, _buffer, bytesInBuffer, count);
    }

    public void Finish(ArraySegment<byte> output)
    {
        if (output.Array == null)
            throw new ArgumentNullException("output.Array");

        if (output.Count != 64)
            throw new ArgumentException("output.Count must be 64");

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

        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 0, _state.x0);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 8, _state.x1);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 16, _state.x2);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 24, _state.x3);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 32, _state.x4);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 40, _state.x5);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 48, _state.x6);
        ByteIntegerConverter.StoreBigEndian64(output.Array, output.Offset + 56, _state.x7);
        _state = default(Array8<ulong>);
    }

    public byte[] Finish()
    {
        var result = new byte[64];
        Finish(new ArraySegment<byte>(result));
        return result;
    }

    public static byte[] Hash(byte[] data)
    {
        return Hash(data, 0, data.Length);
    }

    public static byte[] Hash(byte[] data, int offset, int count)
    {
        var hasher = new Sha512();
        hasher.Update(data, offset, count);
        return hasher.Finish();
    }
}
