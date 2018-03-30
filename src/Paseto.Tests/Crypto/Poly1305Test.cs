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
    public class Poly1305Test
    {
        [Test]
        public void ComputeMacWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => Poly1305.ComputeMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES + 1], new byte[0]));
        }

        [Test]
        public void ComputeMacWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => Poly1305.ComputeMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES - 1], new byte[0]));
        }

        [Test]
        public void VerifyMacWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES + 1], new byte[0], new byte[0]));
        }

        [Test]
        public void VerifyMacWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES - 1], new byte[0], new byte[0]));
        }

        [Test]
        public void RandomMacTest()
        {
            var rnd = new Random();
            for (var i = 0; i < 1000; i++)
            {
                // Arrange
                var data = new byte[rnd.Next(300)];
                rnd.NextBytes(data);
                var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
                rnd.NextBytes(key);

                // Act
                var mac = Poly1305.ComputeMac(key, data);

                // Assert
                Assert.DoesNotThrow(() => Poly1305.VerifyMac(key, data, mac));
            }
        }

        [Test]
        public void VerifyMacFails()
        {
            // Arrange
            var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            key[0] = 1;

            // Act & Assert
            Assert.Throws<CryptographyException>(() => Poly1305.VerifyMac(key, new byte[] { 1 }, new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES]));
        }

        [Test]
        public void ComputeMacTest()
        {
            // Tests against the test vectors in Section 2.5.2 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#section-2.5.2

            // Arrange
            var key = CryptoBytes.FromHexString("85d6be7857556d337f4452fe42d506a8"
                                              + "0103808afb0db2fd4abff6af4149f51b");
            var dat = Encoding.UTF8.GetBytes("Cryptographic Forum Research Group");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("a8061dc1305136c6c22b8baf0c0127a9"), mac);
        }

        [Test]
        public void Poly1305TestVector1()
        {
            // Tests against the test vector 1 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                              + "00000000000000000000000000000000"
                                              + "00000000000000000000000000000000"
                                              + "00000000000000000000000000000000");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("00000000000000000000000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector2()
        {
            // Tests against the test vector 2 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                              + "36e5f6b5c5e06070f0efca96227a863e");
            var dat = Encoding.UTF8.GetBytes("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("36e5f6b5c5e06070f0efca96227a863e"), mac);
        }

        [Test]
        public void Poly1305TestVector3()
        {
            // Tests against the test vector 3 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("36e5f6b5c5e06070f0efca96227a863e"
                                              + "00000000000000000000000000000000");
            var dat = Encoding.UTF8.GetBytes("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("f3477e7cd95417af89a6b8794c310cf0"), mac);
        }

        [Test]
        public void Poly1305TestVector4()
        {
            // Tests against the test vector 4 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("1c9240a5eb55d38af333888604f6b5f0"
                                              + "473917c1402b80099dca5cbc207075c0");
            var dat = CryptoBytes.FromHexString("2754776173206272696c6c69672c2061"
                                              + "6e642074686520736c6974687920746f"
                                              + "7665730a446964206779726520616e64"
                                              + "2067696d626c6520696e207468652077"
                                              + "6162653a0a416c6c206d696d73792077"
                                              + "6572652074686520626f726f676f7665"
                                              + "732c0a416e6420746865206d6f6d6520"
                                              + "7261746873206f757467726162652e");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("4541669a7eaaee61e708dc7cbcc5eb62"), mac);
        }

        [Test]
        public void Poly1305TestVector5()
        {
            // Tests against the test vector 5 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("03000000000000000000000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector6()
        {
            // Tests against the test vector 6 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                              + "ffffffffffffffffffffffffffffffff");
            var dat = CryptoBytes.FromHexString("02000000000000000000000000000000");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("03000000000000000000000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector7()
        {
            // Tests against the test vector 7 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("01000000000000000000000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff"
                                              + "f0ffffffffffffffffffffffffffffff"
                                              + "11000000000000000000000000000000");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("05000000000000000000000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector8()
        {
            // Tests against the test vector 8 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("01000000000000000000000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff"
                                              + "fbfefefefefefefefefefefefefefefe"
                                              + "01010101010101010101010101010101");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("00000000000000000000000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector9()
        {
            // Tests against the test vector 9 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("fdffffffffffffffffffffffffffffff");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("faffffffffffffffffffffffffffffff"), mac);
        }

        [Test]
        public void Poly1305TestVector10()
        {
            // Tests against the test vector 10 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("01000000000000000400000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("e33594d7505e43b90000000000000000"
                                              + "3394d7505e4379cd0100000000000000"
                                              + "00000000000000000000000000000000"
                                              + "01000000000000000000000000000000");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("14000000000000005500000000000000"), mac);
        }

        [Test]
        public void Poly1305TestVector11()
        {
            // Tests against the test vector 11 in Appendix A.3 of RFC 7539.
            // https://tools.ietf.org/html/rfc7539#appendix-A.3

            // Arrange
            var key = CryptoBytes.FromHexString("01000000000000000400000000000000"
                                              + "00000000000000000000000000000000");
            var dat = CryptoBytes.FromHexString("e33594d7505e43b90000000000000000"
                                              + "3394d7505e4379cd0100000000000000"
                                              + "00000000000000000000000000000000");

            // Act
            var mac = Poly1305.ComputeMac(key, dat);

            // Assert
            Assert.AreEqual(CryptoBytes.FromHexString("13000000000000000000000000000000"), mac);
        }
    }
}
