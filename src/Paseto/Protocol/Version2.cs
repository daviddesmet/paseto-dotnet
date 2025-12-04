namespace Paseto.Protocol;

using System;
using System.Linq;
using System.Security.Cryptography;

using NaCl.Core;

using Paseto.Cryptography;
using Paseto.Cryptography.Key;
using Paseto.Extensions;
using Paseto.Internal;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Paseto Version 2.
/// </summary>
/// <seealso cref="Paseto.Protocol.IPasetoProtocolVersion" />
[Obsolete("PASETO Version 2 is deprecated. Implementations should migrate to Version 4.")]
public class Version2 : PasetoProtocolVersion, IPasetoProtocolVersion
{
    internal const int KEY_SIZE_IN_INTS = 8;
    internal const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 3; // 24 crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

    internal const string VERSION = "v2";

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public override string Version => VERSION;

    /// <summary>
    /// Gets the unique version number with which the protocol can be identified.
    /// </summary>
    /// <value>The version number.</value>
    public override int VersionNumber => 2;

    /// <summary>
    /// Gets a value indicating if the protocol supports implicit assertions.
    /// </summary>
    public override bool SupportsImplicitAssertions => false;

    /// <summary>
    /// Generates a Symmetric Key.
    /// </summary>
    /// <returns><see cref="Paseto.Cryptography.Key.PasetoSymmetricKey" /></returns>
    public virtual PasetoSymmetricKey GenerateSymmetricKey()
    {
        var n = new byte[KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(n);

        return new PasetoSymmetricKey(n, this);
    }

    /// <summary>
    /// Generates an Asymmetric Key Pair.
    /// </summary>
    /// <param name="seed">The private seed.</param>
    /// <returns><see cref="Paseto.Cryptography.Key.PasetoAsymmetricKeyPair" /></returns>
    public virtual PasetoAsymmetricKeyPair GenerateAsymmetricKeyPair(byte[] seed = null)
    {
        if (seed is null)
            throw new ArgumentNullException(nameof(seed));

        if (seed.Length != Ed25519.PrivateKeySeedSizeInBytes)
            throw new ArgumentException($"The seed length in bytes must be {Ed25519.PrivateKeySeedSizeInBytes}.");

        Ed25519.KeyPairFromSeed(out var pk, out var sk, seed);

        return new PasetoAsymmetricKeyPair(sk, pk, this);
    }

    /// <summary>
    /// Encrypt a message using a shared secret key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Shared Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">payload or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid</exception>
    public virtual string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "", string assertion = "")
    {
        /*
         * Encrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f`.
         *   1. Before encrypting, first assert that the key being used is intended for use with `v2.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set header `h` to `v2.local`.
         *   3. Generate 24 random bytes from the OS's CSPRNG, `b`.
         *   4. Calculate BLAKE2b of the message `m` with `b` as the key, with an output length of 24. This will be our nonce, `n`.
         *      - This step is to ensure that an RNG failure does not result in a nonce-misuse condition that breaks the security of our stream cipher.
         *   4. Pack `h`, `n`, and `f` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   5. Encrypt the message using XChaCha20-Poly1305, using an AEAD interface such as the one provided in libsodium.
         *      c = crypto_aead_xchacha20poly1305_encrypt(
         *          message = m
         *          aad = preAuth
         *          nonce = n
         *          key = k
         *      );
         *   6. If `f` is:
         *      - Empty: return "h || base64url(n || c)"
         *      - Non-empty: return "h || base64url(n || c) || . || base64url(f)"
         *      - ...where || means "concatenate"
         *      - Note: `base64url()` means Base64url from RFC 4648 without `=` padding.
         *
         */

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (string.IsNullOrWhiteSpace(payload))
            throw new ArgumentNullException(nameof(payload));

        if (!pasetoKey.IsValidFor(this, Purpose.Local))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Local} purpose and {Version} version");

        if (pasetoKey.Key.Length != KEY_SIZE_IN_BYTES)
            throw new ArgumentException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

        var m = GetBytes(payload);

        // Calculate nonce
        var b = GetRandomBytes(NONCE_SIZE_IN_BYTES);
        var blake = new Blake2bMac(b, NONCE_SIZE_IN_BYTES * 8);
        var nonce = blake.ComputeHash(m);

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";
        var pack = PreAuthEncode(new[] { GetBytes(header), nonce, GetBytes(footer) });

        // Encrypt

        /*
         * NaCl.Core
         */
        var algo = new XChaCha20Poly1305(pasetoKey.Key);

        var ciphertext = new byte[m.Length];
        var tag = new byte[16];

        algo.Encrypt(nonce, m, ciphertext, tag, pack);
        var c = CryptoBytes.Combine(ciphertext, tag);

        /*
         * Sodium
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        return SecretAead.Encrypt(payload, nonce, key, aad);
        */

        /*
         * NSec
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        var algo = new NSec.Cryptography.XChaCha20Poly1305();
        using (var k = NSec.Cryptography.Key.Import(algo, key.Span, NSec.Cryptography.KeyBlobFormat.RawSymmetricKey))
            return algo.Encrypt(k, nonce, aad, payload);
        */

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(footer)}";

        return $"{header}{ToBase64Url(nonce.Concat(c).ToArray())}{footer}";
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Shared Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload is not valid</exception>
    public virtual string Decrypt(PasetoSymmetricKey pasetoKey, string token, string footer = "", string assertion = "")
    {
        /*
         * Decrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f`.
         *   1. Before decrypting, first assert that the key being used is intended for use with `v2.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches some expected string `f`, using a constant-time string compare function.
         *   3. Verify that the message begins with `v2.local.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`m` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set
         *          - `n` to the leftmost 24 bytes
         *          - `c` to the middle remainder of the payload, excluding `n`.
         *   5. Pack `h`, `n`, and `f` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   6. Decrypt `c` using XChaCha20-Poly1305, store the result in `p`.
         *      p = crypto_aead_xchacha20poly1305_decrypt(
         *          ciphertext = c
         *          aad = preAuth
         *          nonce = n
         *          key = k
         *      );
         *   7. If decryption failed, throw an exception. Otherwise, return `p`.
         *
         */

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (!pasetoKey.IsValidFor(this, Purpose.Local))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Local} purpose and {Version} version");

        if (pasetoKey.Key.Length != KEY_SIZE_IN_BYTES)
            throw new ArgumentException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";

        if (!token.StartsWith(header))
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Local} purpose and {Version} version");

        var parts = token.Split('.');
        var f = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

        var bytes = FromBase64Url(parts[2]).AsSpan();

        if (bytes.Length < NONCE_SIZE_IN_BYTES)
            throw new PasetoInvalidException("Payload is not valid");

        // Decode the payload
        var nonce = bytes[..NONCE_SIZE_IN_BYTES];
        var payload = bytes[NONCE_SIZE_IN_BYTES..];

        var pack = PreAuthEncode(GetBytes(header), nonce.ToArray(), f);

        // Decrypt

        /*
         * NaCl.Core
         */
        var algo = new XChaCha20Poly1305(pasetoKey.Key);

        var len = payload.Length - 16;
        var plainText = new byte[len];
        var tag = payload[len..];

        algo.Decrypt(nonce, payload[..len], tag, plainText, pack);

        /*
         * Sodium
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        return GetString(SecretAead.Decrypt(payload, nonce, key, associatedData));
        */

        /*
         * NSec
         * Note: Something around the below lines, just XChaCha20Poly1305 is not supported atm.
         *
        var algo = new XChaCha20Poly1305();
        using (var k = Key.Import(algo, key, KeyBlobFormat.RawSymmetricKey))
            return GetString(algo.Decrypt(k, new Nonce(nonce, 0), aad, payload));
        */

        return GetString(plainText);
    }

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric secret key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Secret Key is missing</exception>
    /// <exception cref="System.ArgumentNullException">payload or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid</exception>
    public virtual string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "", string assertion = "")
    {
        /*
         * Sign Specification
         * -------
         *
         * Given a message `m`, Ed25519 secret key `sk`, and optional footer `f` (which defaults to empty string):
         *   1. Before signing, first assert that the key being used is intended for use with `v2.public` tokens, and is the secret key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set `h` to `v2.public`.
         *   3. Pack `h`, `m`, and `f` together using PAE (pre-authentication encoding). We'll call this `m2`.
         *   4. Sign `m2` using Ed25519 `sk`. We'll call this `sig`.
         *      sig = crypto_sign_detached(
         *          message = m2,
         *          private_key = sk
         *      );
         *   5. If `f` is:
         *      - Empty: return "h || base64url(m || sig)"
         *      - Non-empty: return "h || base64url(m || sig) || . || base64url(f)"
         *      - ...where || means "concatenate"
         *      - Note: `base64url()` means Base64url from RFC 4648 without `=` padding.
         *
         */

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (string.IsNullOrWhiteSpace(payload))
            throw new ArgumentNullException(nameof(payload));

        if (!pasetoKey.IsValidFor(this, Purpose.Public))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Public} purpose and {Version} version");

        if (pasetoKey.Key.Length == 0)
            throw new ArgumentException("Secret Key is missing", nameof(pasetoKey));

        var header = $"{Version}.{Purpose.Public.ToDescription()}.";
        var pack = PreAuthEncode(new[] { header, payload, footer });

        var signature = Ed25519.Sign(pack, pasetoKey.Key.Span);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(GetBytes(footer))}";

        return $"{header}{ToBase64Url(GetBytes(payload).Concat(signature).ToArray())}{footer}";
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>a <see cref="PasetoVerifyResult"/> that represents a PASETO token verify operation.</returns>
    /// <exception cref="System.ArgumentException">Public Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload does not contain signature</exception>
    public virtual PasetoVerifyResult Verify(PasetoAsymmetricPublicKey pasetoKey, string token, string footer = "", string assertion = "")
    {
        /*
         * Verify Specification
         * -------
         *
         * Given a signed message `sm`, public key `pk`, and optional footer `f` (which defaults to empty string):
         *   1. Before verifying, first assert that the key being used is intended for use with `v2.public` tokens, and the public key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches `f`, using a constant-time string compare function.
         *   3. Verify that the message begins with `v2.public.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set:
         *          - `s` to the rightmost 64 bytes
         *          - `m` to the leftmost remainder of the payload, excluding `s`
         *   5. Pack `h`, `m`, and `f` together using PAE (pre-authentication encoding). We'll call this `m2`.
         *   6. Use Ed25519 to verify that the signature is valid for the message.
         *      valid = crypto_sign_verify_detached(
         *          signature = s,
         *          message = m2,
         *          publik_key = pk
         *      );
         *   7. If the signature is valid, return `m`. Otherwise, throw an exception.
         *
         */

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (!pasetoKey.IsValidFor(this, Purpose.Public))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Public} purpose and {Version} version");

        if (pasetoKey.Key.Length == 0)
            throw new ArgumentException("Public Key is missing", nameof(pasetoKey));

        if (pasetoKey.Key.Length != KEY_SIZE_IN_BYTES)
            throw new ArgumentException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.", nameof(pasetoKey));

        var header = $"{Version}.{Purpose.Public.ToDescription()}.";

        if (!token.StartsWith(header))
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Public} purpose and {Version} version");

        var parts = token.Split('.');
        var f = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

        var what = GetString(f);

        var body = FromBase64Url(parts[2]);

        const int blockSize = 64;
        if (body.Length < blockSize)
            throw new PasetoInvalidException("Payload does not contain signature");

        // Decode the payload
        var len = body.Length - blockSize;
        var signature = body[len..];
        var payload = body[..len];

        var pack = PreAuthEncode(new[] { GetBytes(header), payload, f });

        var valid = Ed25519.Verify(signature, pack, pasetoKey.Key.Span);

        return valid ? PasetoVerifyResult.Success(GetString(payload)) : PasetoVerifyResult.Failed;
    }
}
