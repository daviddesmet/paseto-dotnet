namespace Paseto.Tests.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Numerics;

    using FluentAssertions;
    using Xunit;

    using Paseto.Cryptography;

    public class Ed25519Tests : IClassFixture<Ed25519TestFixture>
    {
        private readonly Ed25519TestFixture _testFixture;

        public Ed25519Tests(Ed25519TestFixture testFixture) => _testFixture = testFixture;

        [Fact]
        public void KeyPairFromSeed()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey, testCase.Seed);
                TestHelpers.AssertEqualBytes(testCase.PublicKey, publicKey);
                TestHelpers.AssertEqualBytes(testCase.PrivateKey, privateKey);
            }
        }


        [Fact]
        public void KeyPairFromSeedSegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var publicKey = new byte[Ed25519.PublicKeySizeInBytes].Pad();
                var privateKey = new byte[Ed25519.ExpandedPrivateKeySizeInBytes].Pad();
                Ed25519.KeyPairFromSeed(publicKey, privateKey, testCase.Seed.Pad());
                TestHelpers.AssertEqualBytes(testCase.PublicKey, publicKey.UnPad());
                TestHelpers.AssertEqualBytes(testCase.PrivateKey, privateKey.UnPad());
            }
        }

        [Fact]
        public void Sign()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var sig = Ed25519.Sign(testCase.Message, testCase.PrivateKey);
                sig.Length.Should().Be(64);
                TestHelpers.AssertEqualBytes(testCase.Signature, sig);
            }
        }

        [Fact]
        public void Verify()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var success = Ed25519.Verify(testCase.Signature, testCase.Message, testCase.PublicKey);
                success.Should().BeTrue();
            }
        }

        [Fact]
        public void VerifyFail()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            Ed25519.KeyPairFromSeed(out var pk, out var sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Ed25519.Verify(signature, message, pk).Should().BeTrue();
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Ed25519.Verify(signature, modifiedMessage, pk).Should().BeFalse();
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Ed25519.Verify(modifiedSignature, message, pk).Should().BeFalse();
            }
        }

        private byte[] AddL(IEnumerable<byte> input)
        {
            var signedInput = input.Concat(new byte[] { 0 }).ToArray();
            var i = new BigInteger(signedInput);
            var l = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
            i += l;
            var result = i.ToByteArray().Concat(Enumerable.Repeat((byte)0, 32)).Take(32).ToArray();
            return result;
        }

        private byte[] AddLToSignature(byte[] signature) => signature.Take(32).Concat(AddL(signature.Skip(32))).ToArray();

        // Ed25519 is malleable in the `S` part of the signature
        // One can add (a multiple of) the order of the subgroup `l` to `S` without invalidating the signature
        // The implementation only checks if the 3 high bits are zero, which is equivalent to checking if S < 2^253
        // since `l` is only slightly larger than 2^252 this means that you can add `l` to almost every signature
        // *once* without violating this condition, adding it twice will exceed 2^253 causing the signature to be rejected
        // This test serves to document the *is* behaviour, and doesn't define *should* behaviour
        //
        // I consider rejecting signatures with S >= l, but should probably talk to upstream and libsodium before that
        [Fact]
        public void MalleabilityAddL()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            Ed25519.KeyPairFromSeed(out var pk, out var sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Ed25519.Verify(signature, message, pk).Should().BeTrue();
            var modifiedSignature = AddLToSignature(signature);
            Ed25519.Verify(modifiedSignature, message, pk).Should().BeTrue();
            var modifiedSignature2 = AddLToSignature(modifiedSignature);
            Ed25519.Verify(modifiedSignature2, message, pk).Should().BeFalse();
        }

        [Fact]
        public void VerifySegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var success = Ed25519.Verify(testCase.Signature.Pad(), testCase.Message.Pad(), testCase.PublicKey.Pad());
                success.Should().BeTrue();
            }
        }

        [Fact]
        public void VerifyFailSegments()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            Ed25519.KeyPairFromSeed(out var pk, out var sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Ed25519.Verify(signature.Pad(), message.Pad(), pk.Pad()).Should().BeTrue();
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Ed25519.Verify(signature.Pad(), modifiedMessage.Pad(), pk.Pad()).Should().BeFalse();
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Ed25519.Verify(modifiedSignature.Pad(), message.Pad(), pk.Pad()).Should().BeFalse();
            }
        }
    }
}
