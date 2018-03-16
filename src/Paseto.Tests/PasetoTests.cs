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
            using (var rsa = RSA.Create())
                key = rsa.ToJsonString(true);

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
            using (var rsa = RSA.Create())
            {
                //rsa.KeySize = 2048; // Default

                key = rsa.ToJsonString(true);
                pubKey = rsa.ToJsonString(false);
            }
            var sk = GetBytes(key);
            var pk = GetBytes(pubKey);

            // Act
            var token = paseto.Sign(sk, HelloPaseto);
            var verified = paseto.Verify(token, pk).Valid;

            // Assert
            Assert.IsTrue(verified);
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

            var secret = Convert.ToBase64String(sk); //BitConverter.ToString(sk).Replace("-", string.Empty); // Hex Encoded

            // Act
            var token = new PasetoBuilder<Version2>()
                              .WithKey(secret)
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
                              .WithKey(publicKey)
                              .AsPublic()
                              .AndVerifySignature()
                              .Decode(token);

            // Assert
            Assert.IsNotNull(payload);
        }
    }
}
