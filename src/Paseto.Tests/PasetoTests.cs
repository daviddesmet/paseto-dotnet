namespace Paseto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    using NUnit.Framework;

    using Algorithms;
    using Builder;
    using Cryptography;
    using Extensions;
    using Protocol;
    using Utils;
    using static Utils.EncodingHelper;

    [TestFixture]
    public class PasetoTests
    {
        private const string HelloPaseto = "Hello Paseto!";
        private const string PublicKeyV1 = "<RSAKeyValue><Modulus>2Q3n8GRPEbcxAtT+uwsBnY08hhJF+Fby0MM1v5JbwlnQer7HmjKsaS97tbfnl87BwF15eKkxqHI12ntCSezxozhaUrgXCGVAXnUmZoioXTdtJgapFzBob88tLKhpWuoHdweRu9yGcWW3pD771zdFrRwa3h5alC1MAqAMHNid2D56TTsRj4CAfLSZpSsfmswfmHhDGqX7ZN6g/TND6kXjq4fPceFsb6yaKxy0JmtMomVqVTW3ggbVJhqJFOabwZ83/DjwqWEAJvfldz5g9LjvuislO5mJ9QEHBu7lnogKuX5g9PRTqP3c6Kus0/ldZ8CZvwWpxnxnwMRH10/UZ8TepQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string TokenV1 = "v1.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEzMDc1MzMifTzjEcgP2a3p_IrMPuU9bH8OvOmV5Olr8DFK3rFu_7SngF_pZ0cU1X9w590YQeZTy37B1bPouoXZDQ9JDYBfalxG0cNn2aP4iKHgYuyrOqHaUTmbNeooKOvDPwwl6CFO3spTTANLK04qgPJnixeb9mvjby2oM7Qpmn28HAwwr_lSoOMPhiUSCKN4u-SA6G6OddQTuXY-PCV1VtgQA83f0J6Yy3x7MGH9vvqonQSuOG6EGLHJ09p5wXllHQyGZcRm_654aKpwh8CXe3w8ol3OfozGCMFF_TLo_EeX0iKSkE8AQxkrQ-Fe-3lP_t7xPkeNhJPnhAa0-DGLSFQIILsL31M";
        private const string PublicKeyV2 = "rJRRV5JmY3BRUmyWu2CRa1EnUSSNbOgrAMTIsgbX3Z4=";
        private const string TokenV2 = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjIwMTgtMDQtMDdUMDU6MDQ6MDcuOTE5NjM3NVoifTuR3EYYCG12DjhIqPKiVmTkKx2ewCDrYNZHcoewiF-lpFeaFqKW3LkEgnW28UZxrBWA5wrLFCR5FP1qUlMeqQA";
        private const string LocalKeyV2 = "37ZJdkLlZ43aF8UO7GWqi7GrdO0zDZSpSFLNTAdmKdk=";
        private const string LocalTokenV2 = "v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248ENG98mfmCWo7p8qEha5nuyv4lP5y8248lY9VW87NmubNTuceI6BdOfmSOmi9ynEoHk-1CkSWpZygnR_GcRoUdWV3SOwlv2Euc2ZUuhxmrxjlNrPSQf9IEkn9CuOLbhGTDdNOcU9y0N8";
        private const string ExpectedPublicPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T05:04:07.9196375Z\"}";
        private const string ExpectedLocalPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T04:57:18.5865183Z\"}";

        #region Version 1
#if NETCOREAPP2_1 || NET47

        [Test]
        public void Version1SignatureTest()
        {
            // Arrange
            var paseto = new Version1();

            string key = null;
#if NETCOREAPP2_1
            using (var rsa = RSA.Create())
                key = rsa.ToCompatibleXmlString(true);
#elif NET47
            using (var rsa = new RSACng())
                key = rsa.ToXmlString(true);
#endif

            var sk = GetBytes(key);

            // Act
            var token = paseto.Sign(sk, HelloPaseto);

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version1SignatureVerificationTest()
        {
            // Arrange
            var paseto = new Version1();

            string key = null;
            string pubKey = null;
#if NETCOREAPP2_1
            using (var rsa = RSA.Create())
            {
                //rsa.KeySize = 2048; // Default

                key = rsa.ToCompatibleXmlString(true);
                pubKey = rsa.ToCompatibleXmlString(false);
            }
#elif NET47
            using (var rsa = new RSACng())
            {
                //rsa.KeySize = 2048; // Default
                
                key = rsa.ToXmlString(true);
                pubKey = rsa.ToXmlString(false);
            }
#endif
            var sk = GetBytes(key);
            var pk = GetBytes(pubKey);

            // Act
            var token = paseto.Sign(sk, HelloPaseto);
            var verified = paseto.Verify(token, pk).Valid;

            // Assert
            Assert.IsTrue(verified);
        }

        [Test]
        public void Version1BuilderTokenGenerationTest()
        {
            // Arrange
            string key = null;
#if NETCOREAPP2_1
            using (var rsa = RSA.Create())
                key = rsa.ToCompatibleXmlString(true);
#elif NET47
            using (var rsa = new RSACng())
                key = rsa.ToXmlString(true);
#endif

            // Act
            var token = new PasetoBuilder<Version1>()
                              .WithKey(GetBytes(key))
                              .AddClaim("example", HelloPaseto)
                              .Expiration(DateTime.UtcNow.AddHours(24))
                              .AsPublic()
                              .Build();

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version1BuilderTokenDecodingTest()
        {
            // Arrange & Act
            var payload = new PasetoBuilder<Version1>()
                              .WithKey(GetBytes(PublicKeyV1))
                              .AsPublic()
                              .AndVerifySignature()
                              .Decode(TokenV1);

            // Assert
            Assert.IsNotNull(payload);
        }
#endif

        #endregion

        #region Version 2

        [Test]
        public void Version2SignatureTest()
        {
            // Arrange
            var paseto = new Version2();
            var seed = new byte[32];
            Ed25519.KeyPairFromSeed(out var pk, out var sk, seed);

            // Act
            var signature = paseto.Sign(sk, HelloPaseto);

            // Assert
            Assert.IsNotNull(signature);
        }

        [Test]
        public void Version2SignatureNullSecretFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Sign(null, HelloPaseto));
        }

        [Test]
        public void Version2SignatureEmptySecretFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => paseto.Sign(new byte[0], HelloPaseto));
        }

        [Test]
        public void Version2SignatureNullPayloadFails()
        {
            // Arrange
            var paseto = new Version2();
            Ed25519.KeyPairFromSeed(out var pk, out var sk, new byte[32]);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Sign(sk, null));
        }

        [Test]
        public void Version2SignatureEmptyPayloadFails()
        {
            // Arrange
            var paseto = new Version2();
            Ed25519.KeyPairFromSeed(out var pk, out var sk, new byte[32]);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Sign(sk, string.Empty));
        }

        [Test]
        public void Version2SignatureVerificationTest()
        {
            // Arrange
            var paseto = new Version2();
            var seed = new byte[32];
            RandomNumberGenerator.Create().GetBytes(seed);
            Ed25519.KeyPairFromSeed(out var pk, out var sk, seed);

            //var pub = Convert.ToBase64String(pk);

            // Act
            var token = paseto.Sign(sk, HelloPaseto);
            var verified = paseto.Verify(token, pk).Valid;

            // Assert
            Assert.IsTrue(verified);
        }

        [Test]
        public void Version2SignatureVerificationNullTokenFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Verify(null, null));
        }

        [Test]
        public void Version2SignatureVerificationEmptyTokenFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Verify(string.Empty, null));
        }

        [Test]
        public void Version2SignatureVerificationNullPublicKeyFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => paseto.Verify(TokenV2, null));
        }

        [Test]
        public void Version2SignatureVerificationEmptyPublicKeyFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => paseto.Verify(TokenV2, new byte[0]));
        }

        [Test]
        public void Version2SignatureVerificationInvalidPublicKeyFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => paseto.Verify(TokenV2, new byte[16]));
        }

        [Test]
        public void Version2SignatureVerificationInvalidTokenHeaderVersionFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<NotSupportedException>(() => paseto.Verify("v1.public.", new byte[32]));
        }

        [Test]
        public void Version2SignatureVerificationInvalidTokenHeaderFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<NotSupportedException>(() => paseto.Verify("v2.remote.", new byte[32]));
        }

        [Test]
        public void Version2SignatureVerificationInvalidTokenBodyFails()
        {
            // Arrange
            var paseto = new Version2();

            // Act & Assert
            Assert.Throws<NotSupportedException>(() => paseto.Verify("v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZX", new byte[32]));
        }

        [Test]
        public void Version2BuilderPublicTokenGenerationTest()
        {
            // Arrange
            var seed = new byte[32]; // signingKey
            RandomNumberGenerator.Create().GetBytes(seed);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

            //var secret = Convert.ToBase64String(sk); //BitConverter.ToString(sk).Replace("-", string.Empty); // Hex Encoded

            // Act
            var token = new PasetoBuilder<Version2>()
                              .WithKey(sk)
                              .AddClaim("example", HelloPaseto)
                              .Expiration(DateTime.UtcNow.AddHours(24))
                              .AsPublic()
                              .Build();

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version2BuilderLocalTokenGenerationTest()
        {
            // Arrange
            var key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);

            //var secret = Convert.ToBase64String(key); //BitConverter.ToString(key).Replace("-", string.Empty); // Hex Encoded

            // Act
            var token = new PasetoBuilder<Version2>()
                              .WithKey(key)
                              .AddClaim("example", HelloPaseto)
                              .Expiration(DateTime.UtcNow.AddHours(24))
                              .AsLocal()
                              .Build();

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version2BuilderTokenGenerationNullSecretFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(null).Build());

        [Test]
        public void Version2BuilderTokenGenerationEmptySecretFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(new byte[0]).Build());

        [Test]
        public void Version2BuilderTokenGenerationEmptyPayloadFails()
        {
            // Arrange
            var seed = new byte[32]; // signingKey
            RandomNumberGenerator.Create().GetBytes(seed);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(sk).Build());
        }

        [Test]
        public void Version2BuilderPublicTokenDecodingTest()
        {
            // Arrange & Act
            var payload = new PasetoBuilder<Version2>()
                              .WithKey(Convert.FromBase64String(PublicKeyV2))
                              .AsPublic()
                              .Decode(TokenV2);

            // Assert
            Assert.IsNotNull(payload);
            Assert.That(payload, Is.EqualTo(ExpectedPublicPayload));
        }

        [Test]
        public void Version2BuilderLocalTokenDecodingTest()
        {
            // Arrange & Act
            var payload = new PasetoBuilder<Version2>()
                              .WithKey(Convert.FromBase64String(LocalKeyV2))
                              .AsLocal()
                              .Decode(LocalTokenV2);

            // Assert
            Assert.IsNotNull(payload);
            Assert.That(payload, Is.EqualTo(ExpectedLocalPayload));
        }

        [Test]
        public void Version2BuilderTokenDecodingNullPublicKeyFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(null).Decode(null));

        [Test]
        public void Version2BuilderTokenDecodingEmptyPublicKeyFails() => Assert.Throws<InvalidOperationException>(() => new PasetoBuilder<Version2>().WithKey(new byte[0]).Decode(null));

        [Test]
        public void Version2BuilderTokenDecodingNullTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder<Version2>().WithKey(new byte[32]).AsPublic().Decode(null));

        [Test]
        public void Version2BuilderTokenDecodingEmptyTokenFails() => Assert.Throws<ArgumentNullException>(() => new PasetoBuilder<Version2>().WithKey(new byte[32]).AsPublic().Decode(string.Empty));

        [Test]
        public void Version2BuilderTokenDecodingInvalidTokenFails() => Assert.Throws<SignatureVerificationException>(() => new PasetoBuilder<Version2>().WithKey(Convert.FromBase64String(PublicKeyV2)).AsPublic().Decode("v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV2cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs"));

        [Test]
        public void Version2EncoderPublicPurposeTest()
        {
            // Arrange
            var seed = new byte[32]; // signingKey
            RandomNumberGenerator.Create().GetBytes(seed);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(seed);

            //var secret = Convert.ToBase64String(sk); //BitConverter.ToString(sk).Replace("-", string.Empty); // Hex Encoded

            // Act
            var encoder = new PasetoEncoder(cfg => cfg.Use<Version2>(sk)); // defaul is public purpose
            var token = encoder.Encode(new PasetoPayload
            {
                { "example", HelloPaseto },
                { "exp", DateTime.UtcNow.AddHours(24) }
            });

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version2DecoderPublicPurposeTest()
        {
            // Arrange & Act
            var decoder = new PasetoDecoder(cfg => cfg.Use<Version2>(Convert.FromBase64String(PublicKeyV2))); // default is public purpose
            var payload = decoder.Decode(TokenV2);

            // Assert
            Assert.IsNotNull(payload);
            Assert.That(payload, Is.EqualTo(ExpectedPublicPayload));
        }

        [Test]
        public void Version2EncoderLocalPurposeTest()
        {
            // Arrange
            var key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);

            //var secret = Convert.ToBase64String(key); //BitConverter.ToString(key).Replace("-", string.Empty); // Hex Encoded

            // Act
            var encoder = new PasetoEncoder(cfg => cfg.Use<Version2>(key, Purpose.Local));
            var token = encoder.Encode(new PasetoPayload
            {
                { "example", HelloPaseto },
                { "exp", DateTime.UtcNow.AddHours(24) }
            });

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version2DecoderLocalPurposeTest()
        {
            // Arrange & Act
            var decoder = new PasetoDecoder(cfg => cfg.Use<Version2>(Convert.FromBase64String(LocalKeyV2), Purpose.Local));
            var payload = decoder.Decode(LocalTokenV2);

            // Assert
            Assert.IsNotNull(payload);
            Assert.That(payload, Is.EqualTo(ExpectedLocalPayload));
        }

#endregion
    }
}
