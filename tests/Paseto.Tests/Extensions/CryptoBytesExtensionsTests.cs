namespace Paseto.Tests.Extensions;

using System;
using System.Linq;
using Shouldly;
using Paseto.Extensions;
using Paseto.Tests.Crypto;
using Xunit;

public class CryptoBytesExtensionsTests
{
    private readonly byte[] _bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

    [Fact]
    public void Wipe()
    {
        var bytes = (byte[])_bytes.Clone();
        CryptoBytesExtensions.Wipe(bytes);
        bytes.All(b => b == 0).ShouldBeTrue();
    }

    [Fact]
    public void WipeSegment()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
        CryptoBytesExtensions.Wipe(new ArraySegment<byte>(bytes, 2, 5));
        TestHelpers.AssertEqualBytes(wipedBytes, bytes);
    }

    [Fact]
    public void WipeSlice()
    {
        Span<byte> bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        Span<byte> wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
        CryptoBytesExtensions.Wipe(bytes.Slice(2, 5));
        TestHelpers.AssertEqualBytes(wipedBytes.ToArray(), bytes.ToArray());
    }
}