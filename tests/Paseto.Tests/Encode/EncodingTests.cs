namespace Paseto.Tests.Encode;

using System.Collections.Generic;
using System.Text;

using FluentAssertions;
using Xunit;

using static Paseto.Utils.EncodingHelper;

public class EncodingTests
{
    [Fact]
    public void PreAuthWithEmptyArrayTest()
    {
        // Arrange
        const string expected = "\x00\x00\x00\x00\x00\x00\x00\x00";
        var value = new List<byte[]>();

        // Act
        //var pae1 = PAE(value);
        var pae2 = PreAuthEncode(value);

        // Assert
        //Assert.AreEqual(expected, pae1);
        pae2.Should().BeEquivalentTo(Encoding.ASCII.GetBytes(expected));
    }

    [Fact]
    public void PreAuthWithEmptyStringTest()
    {
        // Arrange
        const string expected = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        var value = new List<byte[]>() { Encoding.UTF8.GetBytes(string.Empty) };

        // Act
        //var pae1 = PAE(value);
        var pae2 = PreAuthEncode(value);

        // Assert
        //Assert.AreEqual(expected, pae1);
        pae2.Should().BeEquivalentTo(Encoding.ASCII.GetBytes(expected));
    }

    [Fact]
    public void PreAuthWithStringTest()
    {
        // Arrange
        const string expected = "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test";
        var value = new List<byte[]>() { Encoding.UTF8.GetBytes("test") };

        // Act
        //var pae1 = PAE(value);
        var pae2 = PreAuthEncode(value);

        // Assert
        //Assert.AreEqual(expected, pae1);
        pae2.Should().BeEquivalentTo(Encoding.ASCII.GetBytes(expected));
    }
}
