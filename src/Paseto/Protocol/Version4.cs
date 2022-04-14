namespace Paseto.Protocol;

using System;
using System.Linq;
using System.Security.Cryptography;

using NaCl.Core;
using NaCl.Core.Internal;

using Paseto.Cryptography;
using Paseto.Cryptography.Key;
using Paseto.Extensions;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Paseto Version 4.
/// </summary>
/// <seealso cref="Paseto.Protocol.IPasetoProtocolVersion" />
public class Version4 : PasetoProtocolVersion, IPasetoProtocolVersion
{
    internal const int KEY_SIZE_IN_INTS = 8;
    internal const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int KEYDERIVATION_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int COUNTER_NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 3; // 24

    internal const string VERSION = "v4";

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public override string Version => VERSION;

    /// <summary>
    /// Gets the unique version number with which the protocol can be identified.
    /// </summary>
    /// <value>The version number.</value>
    public override int VersionNumber => 4;

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
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Shared Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">payload or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid</exception>
    public string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "")
    {
        /*
         * Encrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before encrypting, first assert that the key being used is intended for use with `v4.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set header `h` to `v4.local`.
         *   3. Generate 32 random bytes from the OS's CSPRNG to get the nonce, `n`.
         *   4. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`), using keyed BLAKE2b, using the domain separation constants and `n` as the messge, and the input key as the key. The first value will be 56 bytes, the second will be 32 bytes.
         *      The derived key will be the leftmost 32 bytes of the hash output. The remaining 24 bytes will be used as a counter nonce (`n2`):
         *      tmp = crypto_generichash(
         *          msg = "paseto-encryption-key" || n,
         *          key = key,
         *          length = 56
         *      );
         *      Ek = tmp[0:32]
         *      n2 = tmp[32:]
         *      Ak = crypto_generichash(
         *          msg = "paseto-auth-key-for-aead" || n,
         *          key = key,
         *          length = 32
         *      );
         *   5. Encrypt the message using XChaCha20, using `n2` from step 3 as the nonce and `Ek` as the key.
         *      c = crypto_stream_xchacha20_xor(
         *          message = m,
         *          nonce = n2,
         *          key = Ek
         *      );
         *   6. Pack `h`, `n`, `c`, `f` and `i` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   7. Calculate BLAKE2b-MAC of the output of `preAuth`, using `Ak` as the authentication key. We'll call this `t`.
         *      t = crypto_generichash(
         *          msg = preAuth,
         *          key = Ak,
         *          length = 32
         *      );
         *   8. If `f` is:
         *      - Empty: return "h || base64url(n || c || t)"
         *      - Non-empty: return "h || base64url(n || c || t) || . || base64url(f)"
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

        // Generate nonce
        var n = GetRandomBytes(NONCE_SIZE_IN_BYTES);

        // Split the key into an Encryption key and Authentication key
        var tmp = new Blake2bMac(pasetoKey.Key.ToArray(), (KEYDERIVATION_SIZE_IN_BYTES + COUNTER_NONCE_SIZE_IN_BYTES) * 8).ComputeHash(CryptoBytes.Combine(GetBytes(EK_DOMAIN_SEPARATION), n));
        var ek = tmp[..KEYDERIVATION_SIZE_IN_BYTES];
        var n2 = tmp[KEYDERIVATION_SIZE_IN_BYTES..];

        var ak = new Blake2bMac(pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES * 8).ComputeHash(CryptoBytes.Combine(GetBytes(AK_DOMAIN_SEPARATION), n));

        var i = ""; // implicit assertion (add assertion/implicit parameter as string)

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";
        var m = GetBytes(payload);
        var ciphertext = new byte[m.Length];

        // Encrypt
        var algo = new XChaCha20(ek, 0);
        algo.Encrypt(m, n2, ciphertext);

        var pack = PreAuthEncode(GetBytes(header), n, ciphertext, GetBytes(footer), GetBytes(i));

        // Calculate MAC
        var mac = new Blake2bMac(ak, NONCE_SIZE_IN_BYTES * 8).ComputeHash(pack);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(footer)}";

        return $"{header}{ToBase64Url(n.Concat(ciphertext).Concat(mac).ToArray())}{footer}";
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <returns>System.String.</returns>
    /// exception cref="System.ArgumentException">Shared Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload is not valid or Hash is not valid</exception>
    public string Decrypt(string token, PasetoSymmetricKey pasetoKey)
    {
        /*
         * Decrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion i (which defaults to empty string):
         *   1. Before decrypting, first assert that the key being used is intended for use with `v4.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches some expected string `f`, using a constant-time string compare function.
         *      - If `f` is allowed to be a JSON-encoded blob, implementations SHOULD allow users to provide guardrails against invalid JSON tokens. See this [document](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#optional-footer) for specific guidance and example code.
         *   3. Verify that the message begins with `v4.local.`, otherwise throw an exception. This constant will be referred to as `h`.
         *      - **Future-proofing**: If a future PASETO variant allows for encodings other than JSON (e.g., CBOR), future implementations **MAY** also permit those values at this step (e.g. `v4c.local.`).
         *   4. Decode the payload (`m` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set
         *          - `n` to the leftmost 32 bytes
         *          - `t` to the rightmost 32 bytes
         *          - `c` to the middle remainder of the payload, excluding `n` and `t`.
         *   5. Split the key (`k`) into an Encryption key (`Ek`) and an Authentication key (`Ak`), using keyed BLAKE2b, using the domain separation constants and `n` as the message, and the input key as the key. The first value will be 56 bytes, the second will be 32 bytes.
         *      The derived key will be the leftmost 32 bytes of the hash output. The remaining 24 bytes will be used as a counter nonce (`n2`):
         *      tmp = crypto_generichash(
         *          msg = "paseto-encryption-key" || n,
         *          key = key,
         *          length = 56
         *      );
         *      Ek = tmp[0:32]
         *      n2 = tmp[32:]
         *      Ak = crypto_generichash(
         *          msg = "paseto-auth-key-for-aead" || n,
         *          key = key,
         *          length = 32
         *      );
         *   6. Pack `h`, `n`, `c`, `f` and `i` together (in that order) using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   7. Recalculate BLAKE2b-MAC of the output of `preAuth`, using `Ak` as the authentication key. We'll call this `t2`.
         *   8. Compare `t` with `t2` using a constant-time string compare function. If they are not identical, throw an exception.
         *      - You **MUST** use a constant-time string compare function to be compliant. If you do not have one available to you in your programming language/framework, you MUST use [Double HMAC](https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy).
         *      - Common utilities that were not intended for cryptographic comparisons, such as Java's `Array.equals()` or PHP's `==` operator, are explicitly forbidden.
         *   9. Decrypt `c` using XChaCha20, store the result in `p`.
         *      p = crypto_stream_xchacha20_xor(
         *          ciphertext = c
         *          nonce = n2,
         *          key = Ek
         *      );
         *  10. If decryption failed, throw an exception. Otherwise, return `p`.
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
        var footer = GetString(FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty));

        var bytes = FromBase64Url(parts[2]).AsSpan();

        if (bytes.Length < NONCE_SIZE_IN_BYTES + KEYDERIVATION_SIZE_IN_BYTES)
            throw new PasetoInvalidException("Payload is not valid");

        try
        {
            // Decode the payload
            var n = bytes[..NONCE_SIZE_IN_BYTES];
            //var t = bytes[..^KEYDERIVATION_SIZE_IN_BYTES]; // somehow it doesn't return the expected result... ¯\(º_o)/¯
            var c = bytes[NONCE_SIZE_IN_BYTES..^KEYDERIVATION_SIZE_IN_BYTES];
            var tlen = bytes.Length - KEYDERIVATION_SIZE_IN_BYTES;
            var t = bytes[tlen..];

            // Split the key into an Encryption key and Authentication key
            var tmp = new Blake2bMac(pasetoKey.Key.ToArray(), (KEYDERIVATION_SIZE_IN_BYTES + COUNTER_NONCE_SIZE_IN_BYTES) * 8).ComputeHash(CryptoBytes.Combine(GetBytes(EK_DOMAIN_SEPARATION), n.ToArray()));
            var ek = tmp[..KEYDERIVATION_SIZE_IN_BYTES];
            var n2 = tmp[KEYDERIVATION_SIZE_IN_BYTES..];

            var ak = new Blake2bMac(pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES * 8).ComputeHash(CryptoBytes.Combine(GetBytes(AK_DOMAIN_SEPARATION), n.ToArray()));

            var i = ""; // implicit assertion (add assertion/implicit parameter as string)

            var pack = PreAuthEncode(GetBytes(header), n.ToArray(), c.ToArray(), GetBytes(footer), GetBytes(i));

            // Calculate MAC
            var mac = new Blake2bMac(ak, NONCE_SIZE_IN_BYTES * 8);
            var t2 = mac.ComputeHash(pack);

            if (!CryptoBytes.ConstantTimeEquals(t, t2))
                throw new PasetoInvalidException("Hash is not valid");

            // Decrypt
            var plaintext = new byte[c.Length];

            // Encrypt
            var algo = new XChaCha20(ek, 0);
            algo.Encrypt(c, n2, plaintext);

            return GetString(plaintext);
        }
        catch (Exception ex)
        {
            throw new PasetoInvalidException(ex.Message, ex);
        }
    }

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric secret key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Secret Key is missing</exception>
    /// <exception cref="System.ArgumentNullException">payload or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid</exception>
    public string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "")
    {
        /*
         * Sign Specification
         * -------
         *
         * Given a message `m`, Ed25519 secret key `sk`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before signing, first assert that the key being used is intended for use with `v4.public` tokens, and is the secret key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set `h` to `v4.public`.
         *   3. Pack `h`, `m`, `f` and `i` together using PAE (pre-authentication encoding). We'll call this `m2`.
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

        var i = ""; // implicit assertion (add assertion/implicit parameter as string)

        var header = $"{Version}.{Purpose.Public.ToDescription()}.";
        var pack = PreAuthEncode(new[] { header, payload, footer, i });

        var signature = Ed25519.Sign(pack, pasetoKey.Key.ToArray());

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(GetBytes(footer))}";

        return $"{header}{ToBase64Url(GetBytes(payload).Concat(signature).ToArray())}{footer}";
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <returns>a <see cref="PasetoVerifyResult"/> that represents a PASETO token verify operation.</returns>
    /// <exception cref="System.ArgumentException">Public Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload does not contain signature</exception>
    public PasetoVerifyResult Verify(string token, PasetoAsymmetricPublicKey pasetoKey)
    {
        /*
         * Verify Specification
         * -------
         *
         * Given a signed message `sm`, public key `pk`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before verifying, first assert that the key being used is intended for use with `v4.public` tokens, and the public key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches `f`, using a constant-time string compare function.
         *   3. Verify that the message begins with `v4.public.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set:
         *          - `s` to the rightmost 64 bytes
         *          - `m` to the leftmost remainder of the payload, excluding `s`
         *   5. Pack `h`, `m`, `f` and `i` together using PAE (pre-authentication encoding). We'll call this `m2`.
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
        var footer = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

        var body = FromBase64Url(parts[2]);

        const int blockSize = 64;
        if (body.Length < blockSize)
            throw new PasetoInvalidException("Payload does not contain signature");

        // Decode the payload
        var len = body.Length - blockSize;
        var signature = body[..len];
        var payload = body[len..];

        var i = ""; // implicit assertion (add assertion/implicit parameter as string)

        var pack = PreAuthEncode(new[] { GetBytes(header), payload, footer, GetBytes(i) });

        var valid = Ed25519.Verify(signature, pack, pasetoKey.Key.ToArray());

        return valid ? PasetoVerifyResult.Success(GetString(payload)) : PasetoVerifyResult.Failed;
    }
}
