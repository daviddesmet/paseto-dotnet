namespace Paseto.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Algorithms;
    using Extensions;
    using static Utils.EncodingHelper;

    public sealed class Version1 : IPasetoProtocol
    {
        public const string VERSION = "v1";

        public Version1()
        {
            Algorithm = new Version1Algorithm();
        }

        /// <summary>
        /// Gets the unique header version string with which the protocol can be identified.
        /// </summary>
        /// <value>The header version.</value>
        public string Version => VERSION;

        internal IPasetoAlgorithm Algorithm { get; set; }

        public string Encrypt(byte[] key, byte[] nonce, string payload, string footer = "")
        {
            throw new NotImplementedException();

            /*
             * Encrypt Specification
             * -------
             * 
             * Given a message m, key k, and optional footer f (which defaults to empty string):
             *   1. Set header h to v1.local.
             *   2. Generate 32 random bytes from the OS's CSPRNG.
             *   3. Calculate GetNonce() of m and the output of step 2 to get the nonce, n.
             *      - This step is to ensure that an RNG failure does not result in a nonce-misuse condition that breaks the security of our stream cipher.
             *   4. Split the key into an Encryption key (Ek) and Authentication key (Ak), using the leftmost 16 bytes of n as the HKDF salt.
             *   5. Encrypt the message using AES-256-CTR, using Ek as the key and the rightmost 16 bytes of n as the nonce. We'll call this c.
             *   6. Pack h, n, c, and f together using PAE (pre-authentication encoding). We'll call this preAuth.
             *   7. Calculate HMAC-SHA384 of the output of preAuth, using Ak as the authentication key. We'll call this t.
             *   8. If f is:
             *      - Empty: return "h || base64url(n || c || t)"
             *      - Non-empty: return "h || base64url(n || c || t) || . || base64url(f)"
             *      - ...where || means "concatenate"
             *      - Note: base64url() means Base64url from RFC 4648 without = padding.
             *   
             */
        }

        public string Decrypt(string token, byte[] key)
        {
            throw new NotImplementedException();

            /*
             * Decrypt Specification
             * -------
             * 
             * Given a message m, key k, and optional footer f (which defaults to empty string):
             *   1. If f is not empty, verify that the value appended to the token matches f, using a constant-time string compare function. If it does not, throw an exception.
             *   2. Verify that the message begins with v1.local., otherwise throw an exception. This constant will be referred to as h.
             *   3. Decode the payload (m sans h, f, and the optional trailing period between m and f) from base64url to raw binary.
             *      - Set
             *          - n to the leftmost 32 bytes
             *          - t to the rightmost 48 bytes
             *          - c to the middle remainder of the payload, excluding n and t
             *   4. Split the keys using the leftmost 32 bytes of n as the HKDF salt.
             *   5. Pack h, n, c, and f together using PAE (pre-authentication encoding). We'll call this preAuth.
             *   6. Recalculate HASH-HMAC384 of preAuth using Ak as the key. We'll call this t2.
             *   5. Compare t with t2 using a constant-time string compare function. If they are not identical, throw an exception.
             *   6. Decrypt c using AES-256-CTR, using Ek as the key and the rightmost 16 bytes of n as the nonce, and return this value.
             *   
             */
        }

        /// <summary>
        /// Signs the specified payload.
        /// </summary>
        /// <param name="key">The secret key.</param>
        /// <param name="payload">The payload.</param>
        /// <param name="footer">The optional footer.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="ArgumentNullException">
        /// key
        /// or
        /// payload
        /// </exception>
        /// <exception cref="ArgumentException">Secret Key cannot be empty!</exception>
        public string Sign(byte[] key, string payload, string footer = "")
        {
            /*
             * Sign Specification
             * -------
             * 
             * Given a message m, 2048-bit RSA secret key sk, and optional footer f (which defaults to empty string):
             *   1. Set h to v1.public.
             *   2. Pack h, m, and f together using PAE (pre-authentication encoding). We'll call this m2.
             *   3. Sign m2 using RSA with the private key sk. We'll call this sig.
             *      - Padding: PSS
             *      - Public Exponent: 65537
             *      - Hash: SHA384
             *      - MGF: MGF1+SHA384
             *      * Only the above parameters are supported. PKCS1v1.5 is explicitly forbidden.
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
        /// <exception cref="ArgumentNullException">token</exception>
        /// <exception cref="NotSupportedException">
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
             * Given a signed message sm, RSA public key pk, and optional footer f (which defaults to empty string):
             *   1. If f is not empty, verify that the value appended to the token matches f, using a constant-time string compare function. If it does not, throw an exception.
             *   2. Verify that the message begins with v1.public., otherwise throw an exception. This constant will be referred to as h.
             *   3. Decode the payload (sm sans h, f, and the optional trailing period between m and f) from base64url to raw binary.
             *      - Set:
             *          - s to the rightmost 256 bytes
             *          - m to the leftmost remainder of the payload, excluding s
             *   4. Pack h, m, and f together using PAE (pre-authentication encoding). We'll call this m2.
             *   5. Use RSA to verify that the signature is valid for the message:
             *   6. If the signature is valid, return m. Otherwise, throw an exception.
             *   
             */

            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentNullException(nameof(token));

            var header = $"{Version}.{Purpose.Public.ToDescription()}.";
            const int blockSize = 256;

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

        private byte[] GetNonce(string payload, byte[] nonce)
        {
            throw new NotImplementedException();

            /*
             * Get Nonce Specification
             * -------
             * 
             * Given a message (m) and a nonce (n):
             *   1. Calculate HMAC-SHA384 of the message m with n as the key.
             *   2. Return the leftmost 32 bytes of step 1.
             *   
             */
        }
    }
}
