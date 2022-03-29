namespace Paseto.Protocol;

using System;
using System.Linq;

using Paseto.Algorithms;
using Paseto.Extensions;
using Paseto.Cryptography.Key;
using static Utils.EncodingHelper;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

/// <summary>
/// Paseto Version 2.
/// </summary>
/// <seealso cref="Paseto.Protocol.IPasetoProtocolVersion" />
[Obsolete("PASETO Version 2 is deprecated. Implementations should migrate to Version 4.")]
public sealed class Version2 : IPasetoProtocolVersion
{
    public const string VERSION = "v2";

    private const int KEYBYTES = 32;
    private const int NPUBBYTES = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24

    public const int KEY_SIZE_IN_INTS = 8;
    public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    public const int NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 3; // 24 crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

    public Version2() => Algorithm = new Version2Algorithm();

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public string Version => VERSION;

    internal IPasetoAlgorithm Algorithm { get; set; }

    /// <summary>
    /// Encrypt a message using a shared secret key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="PasetoInvalidException">pasetoKey</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">pasetoKey</exception>
    public string Encrypt(PasetoSymmetricKey pasetoKey, byte[] nonce, string payload, string footer = "")
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
            throw new CryptographicException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

        if (nonce is null || nonce.Length != NONCE_SIZE_IN_BYTES)
            nonce = Algorithm.Hash(GetBytes(payload), NONCE_SIZE_IN_BYTES);
        else
            nonce = Algorithm.Hash(GetBytes(payload), nonce, NONCE_SIZE_IN_BYTES);

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";
        var pack = PreAuthEncode(new[] { GetBytes(header), nonce, GetBytes(footer) });

        var encryptedPayload = Algorithm.Encrypt(GetBytes(payload), pack, nonce, pasetoKey.Key);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(footer)}";

        return $"{header}{ToBase64Url(nonce.Concat(encryptedPayload))}{footer}";
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentNullException">token</exception>
    /// <exception cref="System.NotSupportedException">
    /// Token not supported!
    /// or
    /// Token size not supported!
    /// </exception>
    public string Decrypt(string token, PasetoSymmetricKey pasetoKey)
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
            throw new CryptographicException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";

        if (!token.StartsWith(header))
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Local} purpose and {Version} version");

        var parts = token.Split('.');
        var footer = GetString(FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty));

        var bytes = FromBase64Url(parts[2]);

        if (bytes.Length < NONCE_SIZE_IN_BYTES)
            throw new PasetoInvalidException("Token size is not supported!"); // TODO: Change text

        var nonce = bytes.Take(NONCE_SIZE_IN_BYTES).ToArray();
        var payload = bytes.Skip(NONCE_SIZE_IN_BYTES).ToArray();

        //var pack = PreAuthEncode(new[] { header, GetString(nonce), footer }.Select(GetBytes).ToArray());
        var pack = PreAuthEncode(new[] { GetBytes(header), nonce, GetBytes(footer) });

        return Algorithm.Decrypt(payload, pack, nonce, pasetoKey.Key);
    }

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric secret key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <returns>System.String.</returns>
    public string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "")
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

        var signature = Algorithm.Sign(pack, pasetoKey.Key);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(GetBytes(footer))}";

        return $"{header}{ToBase64Url(GetBytes(payload).Concat(signature))}{footer}";
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    /// <exception cref="System.ArgumentNullException">token</exception>
    /// <exception cref="System.NotSupportedException">
    /// The specified token is not supported!
    /// or
    /// Unexpected token size!
    /// </exception>
    public (bool Valid, string Payload) Verify(string token, PasetoAsymmetricPublicKey pasetoKey)
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
         *          message = m2,
         *          private_key = sk
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
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Local} purpose and {Version} version");

        var parts = token.Split('.');
        var footer = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

        var body = FromBase64Url(parts[2]);

        const int blockSize = 64;
        if (body.Length < blockSize)
            throw new PasetoInvalidException("Unexpected token size!"); // TODO: Change text to something like "Payload does not contain signature"

        // TODO: Use Span
        var signature = body.Skip(body.Length - blockSize).ToArray();
        var payload = body.Take(body.Length - blockSize).ToArray();

        var pack = PreAuthEncode(new[] { GetBytes(header), payload, footer });

        return (Algorithm.Verify(pack, signature, pasetoKey.Key), GetString(payload));
    }
}
