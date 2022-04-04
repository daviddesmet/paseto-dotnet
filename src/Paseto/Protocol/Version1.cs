namespace Paseto.Protocol;

using System;
using System.Linq;
using System.Security.Cryptography;

using Paseto.Cryptography.Key;
using Paseto.Extensions;
using static Paseto.Utils.EncodingHelper;

/// <summary>
/// Paseto Version 1.
/// </summary>
/// <seealso cref="Paseto.Protocol.IPasetoProtocolVersion" />
[Obsolete("PASETO Version 1 is deprecated. Implementations should migrate to Version 3.")]
public class Version1 : PasetoProtocolVersion, IPasetoProtocolVersion
{
    public const string VERSION = "v1";

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
    /// <exception cref="PasetoNotSupportedException"></exception>
    public virtual string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "")
    {
#pragma warning disable IDE0022 // Use expression body for methods
        throw new PasetoNotSupportedException("The Local Purpose is not supported in the Version 1 Protocol");
#pragma warning restore IDE0022 // Use expression body for methods

        /*
         * Get Nonce Specification
         * -------
         * 
         * Given a message (m) and a nonce (n):
         *   1. Calculate HMAC-SHA384 of the message m with n as the key.
         *   2. Return the leftmost 32 bytes of step 1.
         *   
         */

        /*
         * Encrypt Specification
         * -------
         * 
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string):
         *   1. Before encrypting, first assert that the key being used is intended for use with `v1.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set header `h` to `v1.local`.
         *   3. Generate 32 random bytes from the OS's CSPRNG, `b`.
         *   4. Calculate `GetNonce()` of `m` and the `b` to get the nonce, `n`.
         *      - This step is to ensure that an RNG failure does not result in a nonce-misuse condition that breaks the security of our stream cipher.
         *   5. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`), using the leftmost 16 bytes of `n` as the HKDF salt.
         *      Ek = hkdf_sha384(
         *          len = 32
         *          ikm = k,
         *          info = "paseto-encryption-key",
         *          salt = n[0:16]
         *      );
         *      Ak = hkdf_sha384(
         *          len = 32
         *          ikm = k,
         *          info = "paseto-auth-key-for-aead",
         *          salt = n[0:16]
         *      );
         *   6. Encrypt the message using `AES-256-CTR`, using `Ek` as the key and the rightmost 16 bytes of `n` as the nonce. We'll call this `c`.
         *      c = aes256ctr_encrypt(
         *          plaintext = m,
         *          nonce = n[16:]
         *          key = Ek
         *      );
         *   7. Pack `h`, `n`, `c`, and `f` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   8. Calculate HMAC-SHA384 of the output of `preAuth`, using `Ak` as the authentication key. We'll call this `t`.
         *   9. If `f` is:
         *      - Empty: return "h || base64url(n || c || t)"
         *      - Non-empty: return "h || base64url(n || c || t) || . || base64url(f)"
         *      - ...where || means "concatenate"
         *      - Note: `base64url()` means Base64url from RFC 4648 without `=` padding.
         *   
         */
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public virtual string Decrypt(string token, PasetoSymmetricKey pasetoKey)
    {
#pragma warning disable IDE0022 // Use expression body for methods
        throw new PasetoNotSupportedException("The Local Purpose is not supported in the Version 1 Protocol");
#pragma warning restore IDE0022 // Use expression body for methods

        /*
         * Decrypt Specification
         * -------
         * 
         * Given a message `m`, key `k`, and optional footer `f` (which defaults to empty string):
         *   1. Before decrypting, first assert that the key being used is intended for use with `v1.local` tokens, and has a length of 256 bits (32 bytes). See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches `f`, using a constant-time string compare function. If it does not, throw an exception.
         *   3. Verify that the message begins with `v1.local.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`m` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set
         *          - `n` to the leftmost 32 bytes
         *          - `t` to the rightmost 48 bytes
         *          - `c` to the middle remainder of the payload, excluding `n` and `t`
         *   5. Split the key (`k`) into an Encryption key (`Ek`) and an Authentication key (`Ak`), using the leftmost 32 bytes of `n` as the HKDF salt.
         *      - For encryption keys, the info parameter for HKDF **MUST** be set to **paseto-encryption-key**.
         *      - For authentication keys, the info parameter for HKDF **MUST** be set to **paseto-auth-key-for-aead**.
         *      - The output length **MUST** be 32 for both keys.
         *      Ek = hkdf_sha384(
         *          len = 32,
         *          ikm = k,
         *          info = "paseto-encryption-key",
         *          salt = n[0:16]
         *      );
         *      Ak = hkdf_sha384(
         *          len = 32,
         *          ikm = k,
         *          info = "paseto-auth-key-for-aead",
         *          salt = n[0:16]
         *      );
         *   6. Pack `h`, `n`, `c`, and `f` together using PAE (pre-authentication encoding). We'll call this `preAuth`.
         *   7. Recalculate HASH-HMAC384 of `preAuth` using `Ak` as the key. We'll call this `t2`.
         *   8. Compare `t` with `t2` using a constant-time string compare function. If they are not identical, throw an exception.
         *   9. Decrypt `c` using `AES-256-CTR`, using `Ek` as the key and the rightmost 16 bytes of `n` as the nonce, and return this value.
         *      return aes256ctr_decrypt(
         *          cipherext = c,
         *          nonce = n[16:].
         *          key = Ek
         *      );
         *   
         */
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
         * Sign Specification
         * -------
         * 
         * Given a message `m`, 2048-bit RSA secret key `sk`, and optional footer `f` (which defaults to empty string):
         *   1. Before signing, first assert that the key being used is intended for use with `v1.public` tokens, and is the secret key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. Set `h` to `v1.public.`
         *   3. Pack `h`, `m`, and `f` together using PAE (pre-authentication encoding). We'll call this `m2`.
         *   4. Sign `m2` using RSA with the private key `sk`. We'll call this `sig`.
         *      - Padding: PSS
         *      - Public Exponent: 65537
         *      - Hash: SHA384
         *      - MGF: MGF1+SHA384
         *      * Only the above parameters are supported. PKCS1v1.5 is explicitly forbidden.
         *      sig = crypto_sign_rsa(
         *          message = m2,
         *          private_key = sk,
         *          padding_mode = "pss",
         *          public_exponent = 65537,
         *          hash = "sha384",
         *          mgf = "mgf1+sha384"
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

        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(pasetoKey.Key.Span));

        var signature = rsa.SignData(pack, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

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
    /// <exception cref="System.ArgumentException">Public Key is missing or invalid</exception>
    /// <exception cref="System.ArgumentNullException">token or pasetoKey</exception>
    /// <exception cref="Paseto.PasetoInvalidException">Key is not valid or The specified token is not valid or Payload does not contain signature</exception>
    public virtual (bool Valid, string Payload) Verify(string token, PasetoAsymmetricPublicKey pasetoKey)
    {
        /*
         * Verify Specification
         * -------
         * 
         * Given a signed message `sm`, RSA public key `pk`, and optional footer `f` (which defaults to empty string):
         *   1. Before verifying, first assert that the key being used is intended for use with `v1.public` tokens, and the public key of the intended keypair. See [Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md) for more information.
         *   2. If `f` is not empty, verify that the value appended to the token matches `f`, using a constant-time string compare function. If it does not, throw an exception.
         *   3. Verify that the message begins with `v1.public.`, otherwise throw an exception. This constant will be referred to as `h`.
         *   4. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period between `m` and `f`) from base64url to raw binary.
         *      - Set:
         *          - `s` to the rightmost 256 bytes
         *          - `m` to the leftmost remainder of the payload, excluding `s`
         *   5. Pack `h`, `m`, and `f` together using PAE (pre-authentication encoding). We'll call this `m2`.
         *   6. Use RSA to verify that the signature is valid for the message:
         *      valid = crypto_sign_rsa_verify(
         *          signature = s,
         *          message = m2,
         *          public_key = pk,
         *          padding_mode = "pss",
         *          public_exponent = 65537,
         *          hash = "sha384",
         *          mgf = "mgf1+sha384"
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

        var header = $"{Version}.{Purpose.Public.ToDescription()}.";

        if (!token.StartsWith(header))
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Public} purpose and {Version} version");

        var parts = token.Split('.');
        var footer = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

        var body = FromBase64Url(parts[2]);

        const int blockSize = 256;
        if (body.Length < blockSize)
            throw new PasetoInvalidException("Payload does not contain signature");

        // Decode the payload
        var len = body.Length - blockSize;
        var signature = body[..len];
        var payload = body[len..];

        var pack = PreAuthEncode(new[] { GetBytes(header), payload, footer });

        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(pasetoKey.Key.Span));

        var valid = rsa.VerifyData(pack, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        return (valid, GetString(payload));
    }
}
