namespace Paseto.Tests.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using NUnit.Framework;

    using Cryptography;
    using Cryptography.Internal;
    using Cryptography.Internal.ChaCha;

    [TestFixture]
    public class ChaCha20Tests
    {
        [Test]
        public void CreateInstanceWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES + 1], 0));
        }

        [Test]
        public void CreateInstanceWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES - 1], 0));
        }

        [Test]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            // Act
            var cipher = new ChaCha20(key, 0);

            // Assert
            Assert.Throws<CryptographyException>(() => cipher.Decrypt(new byte[2]));
        }

        [Test]
        public void EncryptDecrypt1BlockTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var expectedInput = Encoding.UTF8.GetBytes("Hello World!!");

            var cipher = new ChaCha20(key, 0);

            // Act
            var output = cipher.Encrypt(expectedInput);
            var actualInput = cipher.Decrypt(output);

            // Assert
            //Assert.AreEqual(expectedInput, actualInput);
            Assert.IsTrue(CryptoBytes.ConstantTimeEquals(expectedInput, actualInput));
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

                var cipher = new ChaCha20(key, 0);

                for (var j = 0; j < 64; j++)
                {
                    var expectedInput = new byte[rnd.Next(300)];
                    rnd.NextBytes(expectedInput);

                    // Act
                    var output = cipher.Encrypt(expectedInput);
                    var actualInput = cipher.Decrypt(output);

                    // Assert
                    //Assert.AreEqual(expectedInput, actualInput);
                    Assert.IsTrue(CryptoBytes.ConstantTimeEquals(expectedInput, actualInput));
                }
            }
        }

        [Test]
        public void QuarterRoundTest()
        {
            // https://tools.ietf.org/html/rfc7539#section-2.1.1

            // Arrange
            var x = new uint[] { 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567 };

            // Act
            ChaCha20Base.QuarterRound(ref x[0], ref x[1], ref x[2], ref x[3]);

            // Assert
            Assert.AreEqual(new uint[] { 0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb }, x);
        }

        [Test]
        public void QuarterRound16Test()
        {
            // https://tools.ietf.org/html/rfc7539#section-2.2.1

            // Arrange
            var x = new uint[] { 0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320 };

            // Act
            ChaCha20Base.QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);

            // Assert
            Assert.AreEqual(new uint[] { 0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320 }, x);
        }

        [Test]
        public void ChaCha20BlockTestVector()
        {
            // https://tools.ietf.org/html/rfc7539#section-2.3.2

            // Arrange
            var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
            var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a:00:00:00:00".Replace(":", string.Empty));
            var counter = 1;

            // Act
            var chacha20 = new ChaCha20(key, 1);
            var output = chacha20.GetKeyStreamBlock(nonce, counter);

            // Assert
            var expected = new uint[16]
            {
                0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
                0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
                0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
                0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
            };

            Assert.AreEqual(expected, TestHelpers.ToUInt16Array(output));
        }

        [Test]
        public void ChaCha20TestVector()
        {
            // https://tools.ietf.org/html/rfc7539#section-2.4.2

            // Arrange
            foreach (var test in Rfc7539TestVector.Rfc7539TestVectors)
            {
                // Act
                var cipher = new ChaCha20(test.Key, test.InitialCounter);
                var output = cipher.Decrypt(CryptoBytes.Combine(test.Nonce, test.CipherText));

                // Assert
                //Assert.That(output, Is.EqualTo(test.PlainText));
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(test.PlainText, output));
            }
        }

        [Test]
        public void ChaCha20TestVectorTC8()
        {
            // TC8: key: 'All your base are belong to us!, IV: 'IETF2013'
            // Test vector TC8 from RFC draft by J. Strombergson
            // https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-01

            // Arrange
            var key = new byte[32]
            {
                0xC4, 0x6E, 0xC1, 0xB1, 0x8C, 0xE8, 0xA8, 0x78,
                0x72, 0x5A, 0x37, 0xE7, 0x80, 0xDF, 0xB7, 0x35,
                0x1F, 0x68, 0xED, 0x2E, 0x19, 0x4C, 0x79, 0xFB,
                0xC6, 0xAE, 0xBE, 0xE1, 0xA6, 0x67, 0x97, 0x5D
            };

            // The first 4 bytes are set to zero and a large counter
            // is used; this makes the RFC 7539 version of ChaCha20
            // compatible with the original specification by D. J. Bernstein.
            var nonce = new byte[12] { 0x00, 0x00, 0x00, 0x00,
                0x1A, 0xDA, 0x31, 0xD5, 0xCF, 0x68, 0x82, 0x21
            };

            // Act
            var cipher = new ChaCha20(key, 0);
            var block0 = cipher.GetKeyStreamBlock(nonce, 0);
            var block1 = cipher.GetKeyStreamBlock(nonce, 1);

            // Assert
            var expected = new byte[128]
            {
                0xF6, 0x3A, 0x89, 0xB7, 0x5C, 0x22, 0x71, 0xF9,
                0x36, 0x88, 0x16, 0x54, 0x2B, 0xA5, 0x2F, 0x06,
                0xED, 0x49, 0x24, 0x17, 0x92, 0x30, 0x2B, 0x00,
                0xB5, 0xE8, 0xF8, 0x0A, 0xE9, 0xA4, 0x73, 0xAF,
                0xC2, 0x5B, 0x21, 0x8F, 0x51, 0x9A, 0xF0, 0xFD,
                0xD4, 0x06, 0x36, 0x2E, 0x8D, 0x69, 0xDE, 0x7F,
                0x54, 0xC6, 0x04, 0xA6, 0xE0, 0x0F, 0x35, 0x3F,
                0x11, 0x0F, 0x77, 0x1B, 0xDC, 0xA8, 0xAB, 0x92,

                0xE5, 0xFB, 0xC3, 0x4E, 0x60, 0xA1, 0xD9, 0xA9,
                0xDB, 0x17, 0x34, 0x5B, 0x0A, 0x40, 0x27, 0x36,
                0x85, 0x3B, 0xF9, 0x10, 0xB0, 0x60, 0xBD, 0xF1,
                0xF8, 0x97, 0xB6, 0x29, 0x0F, 0x01, 0xD1, 0x38,
                0xAE, 0x2C, 0x4C, 0x90, 0x22, 0x5B, 0xA9, 0xEA,
                0x14, 0xD5, 0x18, 0xF5, 0x59, 0x29, 0xDE, 0xA0,
                0x98, 0xCA, 0x7A, 0x6C, 0xCF, 0xE6, 0x12, 0x27,
                0x05, 0x3C, 0x84, 0xE4, 0x9A, 0x4A, 0x33, 0x32
            };

            //Assert.AreEqual(expected, Combine(block0, block1));
            Assert.IsTrue(CryptoBytes.ConstantTimeEquals(expected, CryptoBytes.Combine(block0, block1)));
        }
    }
}
