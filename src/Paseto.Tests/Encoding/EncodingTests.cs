namespace Paseto.Tests.Encoding
{
    using System.Collections.Generic;
    using System.Text;

    using NUnit.Framework;

    using Utils;
    using static Utils.EncodingHelper;

    [TestFixture]
    public class EncodingTests
    {
        [Test]
        public void PreAuthWithEmptyArrayTest()
        {
            // Arrange
            const string expected = "\x00\x00\x00\x00\x00\x00\x00\x00";
            var value = new List<byte[]>();

            // Act
            var pae1 = PAE(value);
            var pae2 = PreAuthEncode(value);

            // Assert
            Assert.AreEqual(expected, pae1);
            Assert.AreEqual(expected, pae2);
        }

        [Test]
        public void PreAuthWithEmptyStringTest()
        {
            // Arrange
            const string expected = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            var value = new List<byte[]>() { Encoding.UTF8.GetBytes(string.Empty) };

            // Act
            var pae1 = PAE(value);
            var pae2 = PreAuthEncode(value);

            // Assert
            Assert.AreEqual(expected, pae1);
            Assert.AreEqual(expected, pae2);
        }

        [Test]
        public void PreAuthWithStringTest()
        {
            // Arrange
            const string expected = "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test";
            var value = new List<byte[]>() { Encoding.UTF8.GetBytes("test") };

            // Act
            var pae1 = PAE(value);
            var pae2 = PreAuthEncode(value);

            // Assert
            Assert.AreEqual(expected, pae1);
            Assert.AreEqual(expected, pae2);
        }
    }
}
