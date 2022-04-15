namespace Paseto.Protocol;

using Paseto.Cryptography.Key;

/// <summary>
/// Defines the Paseto Protocol Version.
/// </summary>
public interface IPasetoProtocolVersion
{
    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    string Version { get; }

    /// <summary>
    /// Gets the unique version number with which the protocol can be identified.
    /// </summary>
    /// <value>The version number.</value>
    int VersionNumber { get; }

    /// <summary>
    /// Gets a value indicating if the protocol supports implicit assertions.
    /// </summary>
    bool SupportsImplicitAssertions { get; }

    /// <summary>
    /// Generates a Symmetric Key.
    /// </summary>
    /// <returns><see cref="Paseto.Cryptography.Key.PasetoSymmetricKey" /></returns>
    PasetoSymmetricKey GenerateSymmetricKey();

    /// <summary>
    /// Generates an Asymmetric Key Pair.
    /// </summary>
    /// <param name="seed">The private seed if required.</param>
    /// <returns><see cref="Paseto.Cryptography.Key.PasetoAsymmetricKeyPair" /></returns>
    PasetoAsymmetricKeyPair GenerateAsymmetricKeyPair(byte[] seed = null);

    /// <summary>
    /// Encrypt a message using a shared secret key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    string Encrypt(PasetoSymmetricKey pasetoKey, string payload, string footer = "", string assertion = "");

    /// <summary>
    /// Decrypts the specified token using a shared key.
    /// </summary>
    /// <param name="pasetoKey">The symmetric key.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    string Decrypt(PasetoSymmetricKey pasetoKey, string token, string footer = "", string assertion = "");

    /// <summary>
    /// Signs the specified payload.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric secret key.</param>
    /// <param name="payload">The payload.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>System.String.</returns>
    string Sign(PasetoAsymmetricSecretKey pasetoKey, string payload, string footer = "", string assertion = "");

    /// <summary>
    /// Verifies the specified token.
    /// </summary>
    /// <param name="pasetoKey">The asymmetric public key.</param>
    /// <param name="token">The token.</param>
    /// <param name="footer">The optional footer.</param>
    /// <param name="assertion">The optional implicit assertion.</param>
    /// <returns>a <see cref="PasetoVerifyResult"/> that represents a PASETO token verify operation.</returns>
    PasetoVerifyResult Verify(PasetoAsymmetricPublicKey pasetoKey, string token, string footer = "", string assertion = "");
}
