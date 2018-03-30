namespace Paseto.Tests.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using NUnit.Framework;

    using Cryptography;
    using Cryptography.Internal;
    using Cryptography.Internal.ChaCha;

    [TestFixture]
    public class XChaCha20Tests
    {
        [Test]
        public void CreateInstanceWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES + 1], 0));
        }

        [Test]
        public void CreateInstanceWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES - 1], 0));
        }

        [Test]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            // Act
            var cipher = new XChaCha20(key, 0);

            // Assert
            Assert.Throws<CryptographyException>(() => cipher.Decrypt(new byte[2]));
        }

        [Test]
        public void EncryptDecryptNBlocksTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                rnd.NextBytes(key);

                var cipher = new XChaCha20(key, 0);

                for (var j = 0; j < 64; j++)
                {
                    var expectedInput = new byte[rnd.Next(300)];
                    rnd.NextBytes(expectedInput);

                    // Act
                    var output = cipher.Encrypt(expectedInput);
                    var actualInput = cipher.Decrypt(output);

                    // Assert
                    Assert.AreEqual(expectedInput, actualInput);
                }
            }
        }

        [Test]
        public void HChaCha20TestVectors()
        {
            // Arrange
            foreach (var test in HChaCha20TestVector.HChaCha20TestVectors)
            {
                // Act
                var output = XChaCha20.HChaCha20(test.Key, test.Input);

                // Assert
                Assert.That(output, Is.EqualTo(test.Output));
            }
        }
    }
}
