namespace Paseto.Protocol;

using System;
using System.Security.Cryptography;

using NaCl.Core.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using Paseto.Cryptography.Key;
using Paseto.Extensions;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Paseto Version 3.
/// </summary>
/// <seealso cref="Paseto.Protocol.IPasetoProtocolVersion" />
public class Version3 : PasetoProtocolVersion, IPasetoProtocolVersion
{
    public const int KEY_SIZE_IN_INTS = 8;
    public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    public const int NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    public const int SIG_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 12; // 96
    public const int KEYDERIVATION_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 6; // 48

    public const string EK_INFO = "paseto-encryption-key";
    public const string AK_INFO = "paseto-auth-key-for-aead";

    public const string VERSION = "v3";

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public override string Version => VERSION;

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
    public virtual string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "")
    {
        /*
         * Encrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before encrypting, first assert that the key being used is intended for use with `v3.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set header `h` to `v3.local`.
         *   3. Generate 32 random bytes from the OS's CSPRNG to get the nonce, `n`.
         *   4. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`), using HKDF-HMAC-SHA384, with `n` appended to the info rather than the salt.
         *      - The output length **MUST** be 48 for both key derivations.
         *      - The derived key will be the leftmost 32 bytes of the first HKDF derivation.
         *      The remaining 16 bytes of the first key derivation (from which `Ek` is derived) will be used as a counter nonce (`n2`):
         *      tmp = hkdf_sha384(
         *          len = 48,
         *          ikm = k,
         *          info = "paseto-encryption-key" || n,
         *          salt = NULL
         *      );
         *      Ek = tmp[0:32]
         *      n2 = tmp[32:]
         *      Ak = hkdf_sha384(
         *          len = 48,
         *          ikm = k,
         *          info = "paseto-auth-key-for-aead" || n,
         *          salt = NULL
         *      );
         *   5. Encrypt the message using AES-256-CTR, using `Ek` as the key and `n2` as the nonce. We'll call the encrypted output of this step `c`:
         *      c = aes256ctr_encrypt(
         *          plaintext = m,
         *          nonce = n2,
         *          key = Ek
         *      );
         *   6. Pack `h`, `n`, `c`, `f` and `i` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   7. Calculate HMAC-SHA384 of the output of `preAuth`, using `Ak` as the authentication key. We'll call this `t`.
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
        var tmp = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES, info: CryptoBytes.Combine(GetBytes(EK_INFO), n));
        var ek = tmp[..32];
        var n2 = tmp[32..];

        var ak = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES, info: CryptoBytes.Combine(GetBytes(AK_INFO), n));

        // Initialize AES CTR (counter) mode cipher
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");

        // Set cipher parameters to use the encryption key we defined above for encryption
        // Since we are encrypting using the CTR mode / algorithm, the cipher is operating as a stream cipher.
        // For perfect secrecy with a stream cipher, we should be generating a stream of pseudorandom characters called a keystream,
        // then XOR'ing that with the plaintext. Instead, for convenience we are just XOR'ing the first [blocksize] bytes of null values.
        // While convenient, as we only need a single key for two way encryption/decryption, this method is vulnerable to a simple known-plaintext attack
        // As such, it should not be relied upon for true secrecy, only for security through obscurity.
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), n2)); // new byte[16]

        // As this is a stream cipher, you can process bytes chunk by chunk until complete, then close with DoFinal.
        // In our case we don't need a stream, so we simply call DoFinal() to encrypt the entire input at once.
        var c = cipher.DoFinal(GetBytes(payload));

        var i = ""; // implicit assertion (add assertion/implicit parameter as string)

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";
        var pack = PreAuthEncode(new[] { GetBytes(header), n, c, GetBytes(footer), GetBytes(i) });

        // Calculate MAC
        using var hmac = new HMACSHA384(ak);
        var t = hmac.ComputeHash(pack);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(footer)}";

        return $"{header}{ToBase64Url(CryptoBytes.Combine(n, c, t))}{footer}";
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="System.ArgumentException">Shared Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload is not valid or Hash is not valid</exception>
    public virtual string Decrypt(string token, PasetoSymmetricKey pasetoKey)
    {
        /*
         * Decrypt Specification
         * -------
         *
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion i (which defaults to empty string):
         *   1. Before decrypting, first assert that the key being used is intended for use with `v3.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches some expected string `f`, using a constant-time string compare function.
         *      - If `f` is allowed to be a JSON-encoded blob, implementations SHOULD allow users to provide guardrails against invalid JSON tokens. See this [document](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#optional-footer) for specific guidance and example code.
         *   3. Verify that the message begins with `v3.local.`, otherwise throw an exception. This constant will be referred to as `h`.
         *      - **Future-proofing**: If a future PASETO variant allows for encodings other than JSON (e.g., CBOR), future implementations **MAY** also permit those values at this step (e.g. `v3c.local.`).
         *   4. Decode the payload (`m` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set
         *          - `n` to the leftmost 32 bytes
         *          - `t` to the rightmost 48 bytes
         *          - `c` to the middle remainder of the payload, excluding `n` and `t`.
         *   5. Split the key (`k`) into an Encryption key (`Ek`) and an Authentication key (`Ak`), `n` appended to the HKDF info.
         *      - For encryption keys, the info parameter for HKDF MUST be set to `paseto-encryption-key`.
         *      - For authentication keys, the info parameter for HKDF MUST be set to `paseto-auth-key-for-aead`.
         *      - The output length **MUST** be 48 for both key derivations. The leftmost 32 bytes of the first key derivation will produce `Ek`, while the remaining 16 bytes will be the AES nonce `n2`.
         *      tmp = hkdf_sha384(
         *          len = 48,
         *          ikm = k,
         *          info = "paseto-encryption-key" || n,
         *          salt = NULL
         *      );
         *      Ek = tmp[0:32]
         *      n2 = tmp[32:]
         *      Ak = hkdf_sha384(
         *          len = 48,
         *          ikm = k,
         *          info = "paseto-auth-key-for-aead" || n,
         *          salt = NULL
         *      );
         *   6. Pack `h`, `n`, `c`, `f` and `i` together (in that order) using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   7. Recalculate HMAC-SHA-384 of `preAuth` using `Ak` as the key. We'll call this `t2`.
         *   8. Compare `t` with `t2` using a constant-time string compare function. If they are not identical, throw an exception.
         *      - You **MUST** use a constant-time string compare function to be compliant. If you do not have one available to you in your programming language/framework, you MUST use [Double HMAC](https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy).
         *      - Common utilities that were not intended for cryptographic comparisons, such as Java's `Array.equals()` or PHP's `==` operator, are explicitly forbidden.
         *   9. Decrypt `c` using AES-256-CTR, using `Ek` as the key and `n2` as the nonce, then return the plaintext.
         *      return aes256ctr_decrypt(
         *          ciphertext = c
         *          nonce = n2,
         *          key = Ek
         *      );
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
            var tmp = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES, info: CryptoBytes.Combine(GetBytes(EK_INFO), n.ToArray()));
            var ek = tmp[..32];
            var n2 = tmp[32..];

            var ak = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), KEYDERIVATION_SIZE_IN_BYTES, info: CryptoBytes.Combine(GetBytes(AK_INFO), n.ToArray()));

            var i = ""; // implicit assertion (add assertion/implicit parameter as string)

            var pack = PreAuthEncode(new[] { GetBytes(header), n.ToArray(), c.ToArray(), GetBytes(footer), GetBytes(i) });

            // Recalculate MAC
            using var hmac = new HMACSHA384(ak);
            var t2 = hmac.ComputeHash(pack);

            if (!CryptoBytes.ConstantTimeEquals(t, t2))
                throw new PasetoInvalidException("Hash is not valid");

            // Decrypt
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), n2));
            var plaintext = cipher.DoFinal(c.ToArray());

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
    public virtual string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "")
    {
        /*
         * ECDSA Public Key Point Compression
         * -------
         * 
         * Given a public key consisting of two coordinates (X, Y):
         *   1. Set the header to `0x02`.
         *   2. Take the least significant bit of `Y` and add it to the header.
         *   3. Append the X coordinate (in big-endian byte order) to the header.
         *   
         *   In pseudocode:
         *   
         *      lsb(y):
         *          return y[y.length - 1] & 1
         *      pubKeyCompress(x, y):
         *          header = [0x02 + lsb(y)]
         *          return header.concat(x)
         *   
         */

        /*
         * Sign Specification
         * -------
         * 
         * Given a message `m`, 384-bit ECDSA secret key `sk`, and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before signing, first assert that the key being used is intended for use with `v3.public` tokens, and is the secret key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set `h` to `v3.public.`
         *   3. Pack `pk`, `h`, `m`, `f`, and `i` together using PAE (pre-authentication encoding). We'll call this `m2`.
         *      - Note: `pk` is the public key corresponding to `sk` (which **MUST** use [point compression](https://www.secg.org/sec1-v2.pdf)). `pk` **MUST** be 49 bytes long, and the first byte **MUST** be `0x02` or `0x03` 
         *        (depending on the [last significant bit of Y](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf); section 4.3.6, step 2.2). The remaining bytes **MUST** be the X coordinate, using big-endian byte order.
         *   4. Sign `m2` using ECDSA over P-384 AND SHA-384 with the private key `sk`. We'll call this `sig`. The output of `sig` MUST be in the format `r || s` (where `||` means concatenate), for a total length of 96 bytes.
         *      - Signatures **SHOULD** use deterministic nonces ([RFC 6979](https://tools.ietf.org/html/rfc6979)) if possible, to mitigate the risk of [k-value reuse](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/).
         *      - If RFC 6979 is not available in  your programming language, ECDSA **MUST** use a CSPRNG to generate the k-value.
         *      - Hedged signatures (RFC 6979 + additional randomness to provide resilience to fault attacks) are allowed.
         *      sig = crypto_sign_ecdsa_p384(
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

#pragma warning disable IDE0022 // Use expression body for methods
        throw new PasetoNotSupportedException("The Public Purpose is not supported in the Version 3 Protocol");
#pragma warning restore IDE0022 // Use expression body for methods
    }

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
    /// <exception cref="System.ArgumentException">Public Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload does not contain signature</exception>
    public virtual (bool Valid, string Payload) Verify(string token, PasetoAsymmetricPublicKey pasetoKey)
    {
        /*
         * Verify Specification
         * -------
         *
         * Given a signed message `sm`, ECDSA public key `pk` (which MUST use [point compression](https://www.secg.org/sec1-v2.pdf) (Section 2.3.3)), and optional footer `f` (which defaults to empty string), and an optional implicit assertion `i` (which defaults to empty string):
         *   1. Before verifying, first assert that the key being used is intended for use with `v3.public` tokens, and the public key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches `f`, using a constant-time string compare function.
         *   3. Verify that the message begins with `v3.public.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set:
         *          - `s` to the rightmost 96 bytes
         *          - `m` to the leftmost remainder of the payload, excluding `s`
         *   5. Pack `pk`, `h`, `m`, `f` and `i` together (in that order) using PAE (pre-authentication encoding). We'll call this `m2`.
         *      - `pk` **MUST** be 49 bytes long, and the first byte MUST be `0x02` or `0x03` (depending on the sign of the Y coordinate). The remaining bytes **MUST** be the X coordinate, using big-endian byte order.
         *   6. Use ECDSA to verify that the signature is valid for the message.
         *      valid = crypto_sign_ecdsa_p384_verify(
         *          signature = s,
         *          message = m2,
         *          public_key = pk
         *      );
         *   7. If the signature is valid, return `m`. Otherwise, throw an exception.
         *
         */

#pragma warning disable IDE0022 // Use expression body for methods
        throw new PasetoNotSupportedException("The Public Purpose is not supported in the Version 3 Protocol");
#pragma warning restore IDE0022 // Use expression body for methods
    }
}
