namespace Paseto.Tests.Crypto
{
    using System;
    using System.Collections.Generic;

    using NUnit.Framework;

    using Cryptography;
    using Cryptography.Internal;

    [TestFixture]
    public class ChaCha20Poly1305Test
    {
        private const string AEADBadTagExceptionMessage = "AEAD Bad Tag Exception";

        [Test]
        public void CreateInstanceWhenKeyLengthIsGreaterThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new ChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES + 1]));
        }

        [Test]
        public void CreateInstanceWhenKeyLengthIsLessThan32Fails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographyException>(() => new ChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES - 1]));
        }

        [Test]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange & Act
            var cipher = new ChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Assert
            Assert.Throws<CryptographyException>(() => cipher.Decrypt(new byte[27], new byte[1]));
        }

        [Test]
        public void EncryptDecryptTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new ChaCha20Poly1305(key);
            for (var i = 0; i < 100; i++)
            {
                var message = new byte[100];
                rnd.NextBytes(message);

                var aad = new byte[16];
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

                var aead = new ChaCha20Poly1305(key);
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

            var aead = new ChaCha20Poly1305(key);
            var ciphertext = aead.Encrypt(message, aad);

            // Flipping bits
            for (var b = 0; b < ciphertext.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[ciphertext.Length];
                    Array.Copy(ciphertext, modified, ciphertext.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad), AEADBadTagExceptionMessage);
                }
            }

            // Truncate the message
            for (var length = 0; length < ciphertext.Length; length++)
            {
                var modified = new byte[length];
                Array.Copy(ciphertext, modified, length);

                Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad), AEADBadTagExceptionMessage);
            }

            // Modify AAD
            for (var b = 0; b < aad.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[aad.Length];
                    Array.Copy(aad, modified, aad.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Assert.Throws<CryptographyException>(() => aead.Decrypt(modified, aad), AEADBadTagExceptionMessage);
                }
            }
        }

        [Test]
        public void NullPlaintextOrCiphertextFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new ChaCha20Poly1305(key);
            var aad = new byte[] { 1, 2, 3 };

            Assert.Throws<ArgumentNullException>(() => aead.Encrypt(null, aad));
            Assert.Throws<ArgumentNullException>(() => aead.Encrypt(null, null));
            Assert.Throws<ArgumentNullException>(() => aead.Decrypt(null, aad));
            Assert.Throws<ArgumentNullException>(() => aead.Decrypt(null, null));
        }

        [Test]
        public void EmptyAssociatedDataFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new ChaCha20Poly1305(key);
            var aad = new byte[0];

            for (var msgSize = 0; msgSize < 75; msgSize++)
            {
                var message = new byte[msgSize];
                rnd.NextBytes(message);

                // encrypting with aad as a 0-length array
                var ciphertext = aead.Encrypt(message, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);
                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));

                var decrypted2 = aead.Decrypt(ciphertext, null);
                //Assert.AreEqual(message, decrypted2);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted2));

                var badAad = new byte[] { 1, 2, 3 };
                Assert.Throws<CryptographyException>(() => aead.Decrypt(ciphertext, badAad), AEADBadTagExceptionMessage);

                // encrypting with aad equal to null
                ciphertext = aead.Encrypt(message, null);
                decrypted = aead.Decrypt(ciphertext, aad);
                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));

                decrypted2 = aead.Decrypt(ciphertext, null);
                //Assert.AreEqual(message, decrypted2);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted2));

                Assert.Throws<CryptographyException>(() => aead.Decrypt(ciphertext, badAad), AEADBadTagExceptionMessage);
            }
        }

        [Test]
        public void RandomNonceTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new ChaCha20Poly1305(key);

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

        [Test]
        public void ChaCha20Poly1305TestVector()
        {
            // https://tools.ietf.org/html/rfc7539

            // Arrange
            foreach (var test in Rfc7539TestVector.Rfc7539AeadTestVectors)
            {
                // Act
                var aead = new ChaCha20Poly1305(test.Key);
                var ct = aead.Encrypt(test.PlainText, test.Aad, test.Nonce);
                Assert.That(ct, Is.EqualTo(CryptoBytes.Combine(test.CipherText, test.Tag)));

                var output = aead.Decrypt(ct, test.Aad, test.Nonce);

                // Assert
                //Assert.That(output, Is.EqualTo(test.PlainText));
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(test.PlainText, output));
            }
        }

        [Test]
        public void ChaCha20Poly1305TestVector2()
        {
            // https://tools.ietf.org/html/rfc7634

            // Arrange
            foreach (var test in Rfc7539TestVector.Rfc7634AeadTestVectors)
            {
                // Act
                var aead = new ChaCha20Poly1305(test.Key);
                var ct = aead.Encrypt(test.PlainText, test.Aad, test.Nonce);
                Assert.That(ct, Is.EqualTo(CryptoBytes.Combine(test.CipherText, test.Tag)));

                var output = aead.Decrypt(ct, test.Aad, test.Nonce);

                // Assert
                //Assert.That(output, Is.EqualTo(test.PlainText));
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(test.PlainText, output));
            }
        }

        public void WycheproofTestVectors()
        {

        }
    }
}
