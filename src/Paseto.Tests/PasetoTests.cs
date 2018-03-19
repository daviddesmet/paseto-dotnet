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

        [Test]
        public void Version1SignatureTest()
        {
            // Arrange
            var paseto = new Version1();

            string key = null;
#if NETSTANDARD2_0
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
#if NETSTANDARD2_0
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
            using (var rsa = RSA.Create())
                key = rsa.ToCompatibleXmlString(true);

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
            // Arrange
            var publicKey = "<RSAKeyValue><Modulus>2Q3n8GRPEbcxAtT+uwsBnY08hhJF+Fby0MM1v5JbwlnQer7HmjKsaS97tbfnl87BwF15eKkxqHI12ntCSezxozhaUrgXCGVAXnUmZoioXTdtJgapFzBob88tLKhpWuoHdweRu9yGcWW3pD771zdFrRwa3h5alC1MAqAMHNid2D56TTsRj4CAfLSZpSsfmswfmHhDGqX7ZN6g/TND6kXjq4fPceFsb6yaKxy0JmtMomVqVTW3ggbVJhqJFOabwZ83/DjwqWEAJvfldz5g9LjvuislO5mJ9QEHBu7lnogKuX5g9PRTqP3c6Kus0/ldZ8CZvwWpxnxnwMRH10/UZ8TepQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            var token = "v1.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEzMDc1MzMifTzjEcgP2a3p_IrMPuU9bH8OvOmV5Olr8DFK3rFu_7SngF_pZ0cU1X9w590YQeZTy37B1bPouoXZDQ9JDYBfalxG0cNn2aP4iKHgYuyrOqHaUTmbNeooKOvDPwwl6CFO3spTTANLK04qgPJnixeb9mvjby2oM7Qpmn28HAwwr_lSoOMPhiUSCKN4u-SA6G6OddQTuXY-PCV1VtgQA83f0J6Yy3x7MGH9vvqonQSuOG6EGLHJ09p5wXllHQyGZcRm_654aKpwh8CXe3w8ol3OfozGCMFF_TLo_EeX0iKSkE8AQxkrQ-Fe-3lP_t7xPkeNhJPnhAa0-DGLSFQIILsL31M";

            // Act
            var payload = new PasetoBuilder<Version1>()
                              .WithKey(GetBytes(publicKey))
                              .AsPublic()
                              .AndVerifySignature()
                              .Decode(token);

            // Assert
            Assert.IsNotNull(payload);
        }

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
        public void Version2BuilderTokenGenerationTest()
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
        public void Version2BuilderTokenDecodingTest()
        {
            // Arrange
            var publicKey = "g21uHSdjWR8UHQZOSVdkA1cgn9wVpWjruxZDp90lpXs=";
            var token = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs";

            // Act
            var payload = new PasetoBuilder<Version2>()
                              .WithKey(Convert.FromBase64String(publicKey))
                              .AsPublic()
                              .AndVerifySignature()
                              .Decode(token);

            // Assert
            Assert.IsNotNull(payload);
        }

        [Test]
        public void Version2EncoderTest()
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
                { "exp", UnixEpoch.GetSecondsSinceAsString(DateTime.UtcNow.AddHours(24)) }
            });

            // Assert
            Assert.IsNotNull(token);
        }

        [Test]
        public void Version2DecoderTest()
        {
            // Arrange
            var publicKey = "g21uHSdjWR8UHQZOSVdkA1cgn9wVpWjruxZDp90lpXs=";
            var token = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEyNDU0NTAifQ2jznA4Tl8r2PM8xu0FIJhyWkm4SiwvCxavTSFt7bo7JtnsFdWgXBOgbYybi5-NAkmpm94uwJCRjCApOXBSIgs";

            // Act
            var decoder = new PasetoDecoder(cfg => cfg.Use<Version2>(Convert.FromBase64String(publicKey))); // defaul is public purpose
            var payload = decoder.Decode(token);

            // Assert
            Assert.IsNotNull(payload);
        }
    }
}
