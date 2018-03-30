namespace Paseto.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Algorithms;
    using Extensions;
    using static Utils.EncodingHelper;

    /// <summary>
    /// Paseto Version 2.
    /// </summary>
    /// <seealso cref="Paseto.Protocol.IPasetoProtocol" />
    public sealed class Version2 : IPasetoProtocol
    {
        public const string VERSION = "v2";

        private const int KEYBYTES = 32;
        private const int NPUBBYTES = 24; // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24

        public Version2() => Algorithm = new Version2Algorithm();

        /// <summary>
        /// Gets the unique header version string with which the protocol can be identified.
        /// </summary>
        /// <value>The header version.</value>
        public string Version => VERSION;

        internal IPasetoAlgorithm Algorithm { get; set; }

        /// <summary>
        /// Encrypt a message using a shared key.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The footer.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="System.ArgumentOutOfRangeException">key</exception>
        public string Encrypt(byte[] key, byte[] nonce, string payload, string footer = "")
        {
            /*
             * Encrypt Specification
             * -------
             * 
             * Given a message m, key k, and optional footer f.
             *   1. Set header h to v2.local.
             *   2. Generate 24 random bytes from the OS's CSPRNG.
             *   3. Calculate BLAKE2b of the message m with the output of step 2 as the key, with an output length of 24. This will be our nonce, n.
             *      - This step is to ensure that an RNG failure does not result in a nonce-misuse condition that breaks the security of our stream cipher.
             *   4. Pack h, n, and f together using PAE (pre-authentication encoding). We'll call this preAuth.
             *   5. Encrypt the message using XChaCha20-Poly1305, using an AEAD interface such as the one provided in libsodium.
             *   6. If f is: 
             *      - Empty: return "h || base64url(n || c)"
             *      - Non-empty: return "h || base64url(n || c) || . || base64url(f)"
             *      - ...where || means "concatenate"
             *      - Note: base64url() means Base64url from RFC 4648 without = padding.
             *   
             */

            // Validate the length of the key
            if (key is null || key.Length != KEYBYTES)
                throw new ArgumentOutOfRangeException(nameof(key), (key == null) ? 0 : key.Length, string.Format("key must be {0} bytes in length.", KEYBYTES));

            // Validate nonce or otherwise build it
            if (nonce is null || nonce.Length != NPUBBYTES)
                nonce = Algorithm.Hash(payload, NPUBBYTES);

            //var snonce = GetString(nonce);

            // Encrypt
            var header = $"{Version}.{Purpose.Local.ToDescription()}.";
            var pack = PreAuthEncode(new[] { GetBytes(header), nonce, GetBytes(footer) });

            var encryptedPayload = Algorithm.Encrypt(payload, pack, key, nonce);

            if (!string.IsNullOrEmpty(footer))
                footer = $".{ToBase64Url(footer)}";

            return $"{header}{ToBase64Url(nonce.Concat(encryptedPayload))}{footer}";
        }

        /// <summary>
        /// Decrypts the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="key">The symmetric key.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="System.ArgumentNullException">token</exception>
        /// <exception cref="System.NotSupportedException">
        /// Token not supported!
        /// or
        /// Token size not supported!
        /// </exception>
        public string Decrypt(string token, byte[] key)
        {
            /*
             * Decrypt Specification
             * -------
             * 
             * Given a message m, key k, and optional footer f.
             *   1. If f is not empty, verify that the value appended to the token matches f, using a constant-time string compare function. If it does not, throw an exception.
             *   2. Verify that the message begins with v2.local., otherwise throw an exception. This constant will be referred to as h.
             *   3. Decode the payload (m sans h, f, and the optional trailing period between m and f) from base64url to raw binary.
             *      - Set
             *          - n to the leftmost 24 bytes
             *          - c to the middle remainder of the payload, excluding n.
             *   4. Pack h, n, and f together using PAE (pre-authentication encoding). We'll call this preAuth.
             *   5. Decrypt c using XChaCha20-Poly1305, store the result in p.
             *   6. If decryption failed, throw an exception. Otherwise, return p.
             *   
             */

            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token));

            var header = $"{Version}.{Purpose.Local.ToDescription()}.";

            if (!token.StartsWith(header))
                throw new NotSupportedException("The specified token is not supported!");

            var parts = token.Split('.');
            var footer = GetString(FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty));

            var bytes = FromBase64Url(parts[2]);

            if (bytes.Length < NPUBBYTES)
                throw new NotSupportedException("Token size is not supported!");

            var nonce = bytes.Take(NPUBBYTES).ToArray();
            var payload = bytes.Skip(NPUBBYTES).ToArray();

            //var pack = PreAuthEncode(new[] { header, GetString(nonce), footer }.Select(GetBytes).ToArray());
            var pack = PreAuthEncode(new[] { GetBytes(header), nonce, GetBytes(footer) });

            return Algorithm.Decrypt(payload, pack, key, nonce);
        }

        /// <summary>
        /// Signs the specified payload.
        /// </summary>
        /// <param name="key">The secret key.</param>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        public string Sign(byte[] key, string payload, string footer = "")
        {
            /*
             * Sign Specification
             * -------
             * 
             * Given a message m, Ed25519 secret key sk, and optional footer f (which defaults to empty string):
             *   1. Set h to v2.public.
             *   2. Pack h, m, and f together using PAE (pre-authentication encoding). We'll call this m2.
             *   3. Sign m2 using Ed25519 sk. We'll call this sig.
             *   4. If f is:
             *      - Empty: return "h || base64url(m || sig)"
             *      - Non-empty: return "h || base64url(m || sig) || . || base64url(f)"
             *      - ...where || means "concatenate"
             *      - Note: base64url() means Base64url from RFC 4648 without = padding.
             *   
             */

            if (key is null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                throw new ArgumentException("Secret Key cannot be empty!");

            if (string.IsNullOrWhiteSpace(payload))
                throw new ArgumentNullException(nameof(payload));

            var header = $"{Version}.{Purpose.Public.ToDescription()}.";
            var pack = PreAuthEncode(new[] { header, payload, footer });

            var signature = Algorithm.Sign(pack, key);

            if (!string.IsNullOrEmpty(footer))
                footer = $".{ToBase64Url(GetBytes(footer))}";

            return $"{header}{ToBase64Url(GetBytes(payload).Concat(signature))}{footer}";
        }

        /// <summary>
        /// Verifies the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="key">The public key.</param>
        /// <returns><c>true</c> if verified, <c>false</c> otherwise.</returns>
        /// <exception cref="System.ArgumentNullException">token</exception>
        /// <exception cref="System.NotSupportedException">
        /// The specified token is not supported!
        /// or
        /// Unexpected token size!
        /// </exception>
        public (bool Valid, string Payload) Verify(string token, byte[] key)
        {
            /*
             * Verify Specification
             * -------
             * 
             * Given a signed message sm, public key pk, and optional footer f (which defaults to empty string):
             *   1. If f is not empty, verify that the value appended to the token matches f, using a constant-time string compare function. If it does not, throw an exception.
             *   2. Verify that the message begins with v2.public., otherwise throw an exception. This constant will be referred to as h.
             *   3. Decode the payload (sm sans h, f, and the optional trailing period between m and f) from base64url to raw binary.
             *      - Set:
             *          - s to the rightmost 64 bytes
             *          - m to the leftmost remainder of the payload, excluding s
             *   4. Pack h, m, and f together using PAE (pre-authentication encoding). We'll call this m2.
             *   5. Use Ed25519 to verify that the signature is valid for the message.
             *   6. If the signature is valid, return m. Otherwise, throw an exception.
             *   
             */

            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token));

            if (key is null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                throw new ArgumentException("Public key cannot be empty!");

            if (key.Length != KEYBYTES)
                throw new ArgumentException("Invalid public key size!");

            var header = $"{Version}.{Purpose.Public.ToDescription()}.";
            const int blockSize = 64;

            if (!token.StartsWith(header))
                throw new NotSupportedException("The specified token is not supported!");

            var parts = token.Split('.');
            var footer = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);

            var body = FromBase64Url(parts[2]);

            if (body.Length < blockSize)
                throw new NotSupportedException("Unexpected token size!");

            var signature = body.Skip(body.Length - blockSize).ToArray();
            var payload = body.Take(body.Length - blockSize).ToArray();

            var pack = PreAuthEncode(new[] { GetBytes(header), payload, footer });

            return (Algorithm.Verify(pack, signature, key), GetString(payload));
        }
    }
}
