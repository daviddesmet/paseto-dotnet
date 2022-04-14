using System.Security.Cryptography;

namespace Paseto.Protocol;

public abstract class PasetoProtocolVersion
{
    public const string EK_DOMAIN_SEPARATION = "paseto-encryption-key";
    public const string AK_DOMAIN_SEPARATION = "paseto-auth-key-for-aead";

    /// <summary>
    /// Gets the unique header version string with which the protocol can be identified.
    /// </summary>
    /// <value>The header version.</value>
    public abstract string Version { get; }

    /// <summary>
    /// Gets the unique version number with which the protocol can be identified.
    /// </summary>
    /// <value>The version number.</value>
    public abstract int VersionNumber { get; }

    /// <summary>
    /// Gets the nonce which was set for testing purposes;
    /// </summary>
    protected byte[] TestNonce { get; set; }

    /// <summary>
    /// Sets the nonce used exclusively for testing purposes.
    /// </summary>
    /// <param name="nonce"></param>
    internal void SetTestNonce(byte[] nonce) => TestNonce = nonce;

    /// <summary>
    /// Get a random sequence of bytes using a cryptographically secure pseudorandom number generator (CSPRNG)
    /// </summary>
    /// <param name="size">The size of the array of bytes.</param>
    /// <returns></returns>
    protected byte[] GetRandomBytes(int size)
    {
        if (TestNonce != null && TestNonce.Length == size)
            return TestNonce;

        var n = new byte[size];
        RandomNumberGenerator.Fill(n);
        return n;
    }
}
