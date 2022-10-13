namespace Paseto.Tests.Crypto.Argon2;

using System.Linq;
using Paseto.Cryptography.Internal.Argon2;
using Xunit;

public class LittleEndianActiveStreamTests
{
    [Fact]
    public void EndsWhereLastByteAvailable()
    {
        var stream = new LittleEndianActiveStream();

        stream.Expose((ushort)0x4501);
        var buffer = new byte[4];

        Assert.Equal(2, stream.Read(buffer, 0, 4));
        Assert.Equal(0x01, buffer[0]);
        Assert.Equal(0x45, buffer[1]);
    }

    [Fact]
    public void CrossesBoundariesAsExpected()
    {
        var stream = new LittleEndianActiveStream();

        stream.Expose((uint)0x01010101);
        stream.Expose((uint)0x30303030);
        stream.Expose((uint)0x0a0a0a0a);
        stream.Expose(new byte[] { 0x45, 0x61 });

        var buffer = new byte[5];
        Assert.Equal(5, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0x1, 0x1, 0x1, 0x1, 0x30 }, buffer);

        Assert.Equal(5, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0x30, 0x30, 0x30, 0x0a, 0x0a }, buffer);

        Assert.Equal(4, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0x0a, 0x0a, 0x45, 0x61 }, buffer.Take(4));
    }

    [Fact]
    public void AllocationIsManagedAppropriately()
    {
        var stream = new LittleEndianActiveStream();

        stream.Expose((uint)0x01010101);
        stream.Expose((uint)0x30303030);
        stream.Expose(new byte[] { 0x45, 0x61, 0xac, 0x4c, 0xf0, 0x00, 0x0b });

        var buffer = new byte[5];
        Assert.Equal(5, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0x1, 0x1, 0x1, 0x1, 0x30 }, buffer);

        Assert.Equal(5, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0x30, 0x30, 0x30, 0x45, 0x61 }, buffer);

        Assert.Equal(5, stream.Read(buffer, 0, 5));
        Assert.Equal(new byte[] { 0xac, 0x4c, 0xf0, 0x00, 0x0b }, buffer);
    }
}