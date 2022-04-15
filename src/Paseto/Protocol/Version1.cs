namespace Paseto.Protocol;

using System;
using System.Linq;
using System.Security.Cryptography;

using NaCl.Core.Internal;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

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
    internal const int KEY_SIZE_IN_INTS = 8;

    internal const int SYM_KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int SYM_NONCE_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int SYM_KEYDERIVATION_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    internal const int SYM_NONCE_SPLIT_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 2; // 16

    internal const int ASYM_KEY_SIZE_IN_BITS = 2048;
    internal const int ASYM_KEY_SIZE_IN_BYTES = ASYM_KEY_SIZE_IN_BITS / 8; // 256

    internal const string VERSION = "v1";

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public override string Version => VERSION;

    /// <summary>
    /// Gets the unique version number with which the protocol can be identified.
    /// </summary>
    /// <value>The version number.</value>
    public override int VersionNumber => 1;

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
        var n = new byte[SYM_KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(n);

        return new PasetoSymmetricKey(n, this);
    }

    /// <summary>
    /// Generates an Asymmetric Key Pair.
    /// </summary>
    /// <param name="seed">The private seed which is not required.</param>
    /// <returns><see cref="Paseto.Cryptography.Key.PasetoAsymmetricKeyPair" /></returns>
    public virtual PasetoAsymmetricKeyPair GenerateAsymmetricKeyPair(byte[] seed = null)
    {
        using var rsa = RSA.Create();
        rsa.KeySize = ASYM_KEY_SIZE_IN_BITS;
        var sk = rsa.ExportRSAPrivateKey();
        var pk = rsa.ExportRSAPublicKey();

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
    /// <exception cref="PasetoNotSupportedException"></exception>
    public virtual string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "", string assertion = "")
    {
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

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (string.IsNullOrWhiteSpace(payload))
            throw new ArgumentNullException(nameof(payload));

        if (!pasetoKey.IsValidFor(this, Purpose.Local))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Local} purpose and {Version} version");

        if (pasetoKey.Key.Length != SYM_KEY_SIZE_IN_BYTES)
            throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}.");

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";
        var m = GetBytes(payload);
        var f = GetBytes(footer);

        // Calculate nonce
        var b = GetRandomBytes(SYM_NONCE_SIZE_IN_BYTES);
        using var hmacn = new HMACSHA384(b);
        var nonce = hmacn.ComputeHash(m)[..SYM_NONCE_SIZE_IN_BYTES];

        // Split the key into an Encryption key and Authentication key
        var ek = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), SYM_KEYDERIVATION_SIZE_IN_BYTES, info: GetBytes(EK_DOMAIN_SEPARATION), salt: nonce[..SYM_NONCE_SPLIT_SIZE_IN_BYTES]);
        var ak = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), SYM_KEYDERIVATION_SIZE_IN_BYTES, info: GetBytes(AK_DOMAIN_SEPARATION), salt: nonce[..SYM_NONCE_SPLIT_SIZE_IN_BYTES]);

        // Encrypt using AES CTR (counter) mode cipher
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), nonce[SYM_NONCE_SPLIT_SIZE_IN_BYTES..]));
        var c = cipher.DoFinal(GetBytes(payload));

        var pack = PreAuthEncode(GetBytes(header), nonce, c, f);

        // Calculate MAC
        using var hmac = new HMACSHA384(ak);
        var t = hmac.ComputeHash(pack);

        if (!string.IsNullOrEmpty(footer))
            footer = $".{ToBase64Url(footer)}";

        return $"{header}{ToBase64Url(CryptoBytes.Combine(nonce, c, t))}{footer}";
    }

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    /// <exception cref="PasetoNotSupportedException"></exception>
    public virtual string Decrypt(PasetoSymmetricKey pasetoKey, string token, string footer = "", string assertion = "")
    {
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

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        if (pasetoKey is null)
            throw new ArgumentNullException(nameof(pasetoKey));

        if (!pasetoKey.IsValidFor(this, Purpose.Local))
            throw new PasetoInvalidException($"Key is not valid for {Purpose.Local} purpose and {Version} version");

        if (pasetoKey.Key.Length != SYM_KEY_SIZE_IN_BYTES)
            throw new ArgumentException($"The key length in bytes must be {SYM_KEY_SIZE_IN_BYTES}.");

        var header = $"{Version}.{Purpose.Local.ToDescription()}.";

        if (!token.StartsWith(header))
            throw new PasetoInvalidException($"The specified token is not valid for {Purpose.Local} purpose and {Version} version");

        var parts = token.Split('.');
        var f = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);
        VerifyFooter(f, footer);

        var bytes = FromBase64Url(parts[2]).AsSpan();

        if (bytes.Length < SYM_NONCE_SIZE_IN_BYTES + SYM_KEYDERIVATION_SIZE_IN_BYTES + SYM_NONCE_SPLIT_SIZE_IN_BYTES)
            throw new PasetoInvalidException("Payload is not valid");

        try
        {
            // Decode the payload
            var right = SYM_NONCE_SIZE_IN_BYTES + SYM_NONCE_SPLIT_SIZE_IN_BYTES;
            var n = bytes[..SYM_NONCE_SIZE_IN_BYTES];
            //var t = bytes[..^right]; // somehow it doesn't return the expected result... ¯\(º_o)/¯
            var c = bytes[SYM_NONCE_SIZE_IN_BYTES..^right];
            var tlen = bytes.Length - right;
            var t = bytes[tlen..];

            // Split the key into an Encryption key and Authentication key
            var ek = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), SYM_KEYDERIVATION_SIZE_IN_BYTES, info: GetBytes(EK_DOMAIN_SEPARATION), salt: n[..SYM_NONCE_SPLIT_SIZE_IN_BYTES].ToArray());
            var ak = HKDF.DeriveKey(HashAlgorithmName.SHA384, pasetoKey.Key.ToArray(), SYM_KEYDERIVATION_SIZE_IN_BYTES, info: GetBytes(AK_DOMAIN_SEPARATION), salt: n[..SYM_NONCE_SPLIT_SIZE_IN_BYTES].ToArray());

            var pack = PreAuthEncode(GetBytes(header), n.ToArray(), c.ToArray(), f);

            // Recalculate MAC
            using var hmac = new HMACSHA384(ak);
            var t2 = hmac.ComputeHash(pack);

            if (!CryptoBytes.ConstantTimeEquals(t, t2))
                throw new PasetoInvalidException("Hash is not valid");

            // Decrypt
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), n[SYM_NONCE_SPLIT_SIZE_IN_BYTES..].ToArray()));
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

        /*
         * BCL doesn't support RSA-PSS SHA-384 MGF1
         *
        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(pasetoKey.Key.Span));

        var signature = rsa.SignData(pack, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        */

        /*
         * Using Bouncy Castle
         */

        // Create Private Key
        RsaPrivateCrtKeyParameters privKeyParams;
        try
        {
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(pasetoKey.Key.Span.ToArray());
            var privKeyStruct = RsaPrivateKeyStructure.GetInstance(seq);
            privKeyParams = new RsaPrivateCrtKeyParameters(privKeyStruct.Modulus, privKeyStruct.PublicExponent, privKeyStruct.PrivateExponent, privKeyStruct.Prime1, privKeyStruct.Prime2, privKeyStruct.Exponent1, privKeyStruct.Exponent2, privKeyStruct.Coefficient);

            if (privKeyParams.Modulus.BitLength != ASYM_KEY_SIZE_IN_BITS)
                throw new ArgumentException($"The key length in bytes must be {ASYM_KEY_SIZE_IN_BYTES}.");
        }
        catch (Exception)
        {
            throw new ArgumentException("Secret Key is invalid", nameof(pasetoKey));
        }

        // Sign using RSA-PSS, SHA-384, MGF1(SHA-384)
        var rsa = SignerUtilities.GetSigner("SHA384withRSAandMGF1");
        rsa.Init(true, privKeyParams);

        rsa.BlockUpdate(pack, 0, pack.Length);
        var signature = rsa.GenerateSignature();

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
        var f = FromBase64Url(parts.Length > 3 ? parts[3] : string.Empty);
        VerifyFooter(f, footer);

        var body = FromBase64Url(parts[2]);

        const int blockSize = 256;
        if (body.Length < blockSize)
            throw new PasetoInvalidException("Payload does not contain signature");

        // Decode the payload
        var len = body.Length - blockSize;
        var signature = body[len..];
        var payload = body[..len];

        var pack = PreAuthEncode(new[] { GetBytes(header), payload, f });

        /*
         * BCL doesn't support RSA-PSS SHA-384 MGF1
         *
        using var rsa = RSA.Create();
        //rsa.KeySize = 2048; // Default
        rsa.FromCompatibleXmlString(GetString(pasetoKey.Key.Span));

        var valid = rsa.VerifyData(pack, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        */

        /*
         * Using Bouncy Castle
         */

        // Create Public Key
        var seq = (Asn1Sequence)Asn1Object.FromByteArray(pasetoKey.Key.Span.ToArray());
        var pubKeyStruct = RsaPublicKeyStructure.GetInstance(seq);
        var pubKeyParams = new RsaKeyParameters(false, pubKeyStruct.Modulus, pubKeyStruct.PublicExponent);

        // Verify signature using RSA-PSS, SHA-384, MGF1(SHA-384)
        var rsa = SignerUtilities.GetSigner("SHA384withRSAandMGF1");
        rsa.Init(false, pubKeyParams);

        rsa.BlockUpdate(pack, 0, pack.Length);
        var valid = rsa.VerifySignature(signature);

        return valid ? PasetoVerifyResult.Success(GetString(payload)) : PasetoVerifyResult.Failed;
    }
}
