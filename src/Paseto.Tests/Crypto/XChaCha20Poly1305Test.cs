namespace Paseto.Tests.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using NUnit.Framework;

    using Cryptography;
    using Cryptography.Internal;

    [TestFixture]
    public class XChaCha20Poly1305Test
    {
        //private const string AEADBadTagExceptionMessage = "AEAD Bad Tag Exception";
        //private static byte[] KEY = CryptoBytes.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        //private static string NONCE = "07000000404142434445464748494a4b0000000000000000";
        //private static byte[] AD = CryptoBytes.FromHexString("50515253c0c1c2c3c4c5c6c7");

        [Test]
        public void CreateInstanceWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES + 1]));
        }

        [Test]
        public void CreateInstanceWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES - 1]));
        }

        [Test]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange & Act
            var cipher = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Assert
            Assert.Throws<CryptographyException>(() => cipher.Decrypt(new byte[27], new byte[1]));
        }

        [Test]
        public void EncryptDecryptTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);
            for (var i = 0; i < 100; i++)
            {
                var message = new byte[100]; // rnd.Next(100)
                rnd.NextBytes(message);

                var aad = new byte[16]; // rnd.Next(16)
                rnd.NextBytes(aad);

                var ciphertext = aead.Encrypt(message, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);

                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));
            }
        }

        [Test]
        public void EncryptDecryptLongMessagesTest()
        {
            var rnd = new Random();

            var dataSize = 16;
            while (dataSize <= (1 << 24))
            {
                var plaintext = new byte[dataSize];
                rnd.NextBytes(plaintext);

                var aad = new byte[dataSize / 3];
                rnd.NextBytes(aad);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                rnd.NextBytes(key);

                var aead = new XChaCha20Poly1305(key);
                var ciphertext = aead.Encrypt(plaintext, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);

                //Assert.AreEqual(plaintext, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(plaintext, decrypted));
                dataSize += 5 * dataSize / 11;
            }
        }

        [Test]
        public void ModifiedCiphertextFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aad = new byte[16];
            rnd.NextBytes(aad);

            var message = new byte[32];
            rnd.NextBytes(message);

            var aead = new XChaCha20Poly1305(key);
            var ciphertext = aead.Encrypt(message, aad);

            // Flipping bits
            for (var b = 0; b < ciphertext.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[ciphertext.Length];
                    Array.Copy(ciphertext, modified, ciphertext.Length);

                    modified[b] ^= (byte)(1 << bit);

                    //Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad));
                }
            }

            // Truncate the message
            for (var length = 0; length < ciphertext.Length; length++)
            {
                var modified = new byte[length];
                Array.Copy(ciphertext, modified, length);

                Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad));
            }

            // Modify AAD
            for (var b = 0; b < aad.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[aad.Length];
                    Array.Copy(aad, modified, aad.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad));
                }
            }
        }

        [Test]
        public void RandomNonceTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);

            var message = new byte[0];
            var aad = new byte[0];
            var ciphertexts = new HashSet<string>();
            var samples = 1 << 17;

            for (var i = 0; i < samples; i++)
            {
                var ct = aead.Encrypt(message, aad);
                var ctHex = CryptoBytes.ToHexStringLower(ct);

                Assert.IsFalse(ciphertexts.Contains(ctHex));
                ciphertexts.Add(ctHex);
            }

            Assert.AreEqual(samples, ciphertexts.Count);
        }

        /*
        [Test]
        public void LibSodiumTestVector()
        {
            // Arrange
            var data = CryptoBytes.ToHexStringLower(Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."));
            var cipher = new XChaCha20Poly1305(KEY);
            var c = CryptoBytes.FromHexString(NONCE
                                            + "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8"
                                            + "b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faee"
                                            + "bbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b"
                                            + "718a62863730a2702bb76366116bed09e0fd"
                                            + "5c6d84b6b0c1abaf249d5dd0f7f5a7ea"); // tag

            // Act & Assert
            Assert.That(CryptoBytes.ToHexStringLower(cipher.Decrypt(c, AD)), Is.EqualTo(data));
        }

        [Test]
        public void EmptyAdWithLibSodiumTestVector()
        {
            // Arrange
            var data = CryptoBytes.ToHexStringLower(Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."));
            var cipher = new XChaCha20Poly1305(KEY);
            var c = CryptoBytes.FromHexString(NONCE
                                            + "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8"
                                            + "b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faee"
                                            + "bbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b"
                                            + "718a62863730a2702bb76366116bed09e0fd"
                                            + "d4c860b7074be894fac9697399be5cc1"); // tag

            // Act & Assert
            Assert.That(CryptoBytes.ToHexStringLower(cipher.Decrypt(c, new byte[0])), Is.EqualTo(data));
        }
        */
    }
}
