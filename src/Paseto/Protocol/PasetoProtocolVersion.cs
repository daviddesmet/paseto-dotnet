namespace Paseto.Protocol;

using System.Security.Cryptography;
using Paseto.Internal;
using static Paseto.Utils.EncodingHelper;

public abstract class PasetoProtocolVersion
{
    protected const string EK_DOMAIN_SEPARATION = "paseto-encryption-key";
    protected const string AK_DOMAIN_SEPARATION = "paseto-auth-key-for-aead";

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
    /// Gets a value indicating if the protocol supports implicit assertions.
    /// </summary>
    public abstract bool SupportsImplicitAssertions { get; }

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
    /// <remarks>
    /// A test nonce, when set, is consumed on first use (one-shot) so a deterministic nonce can never
    /// silently persist across operations and cause nonce reuse.
    /// </remarks>
    /// <param name="size">The size of the array of bytes.</param>
    /// <returns></returns>
    protected byte[] GetRandomBytes(int size)
    {
        if (TestNonce != null && TestNonce.Length == size)
        {
            var testNonce = TestNonce;
            TestNonce = null;
            return testNonce;
        }

        var n = new byte[size];
        Rng.Fill(n);
        return n;
    }

    protected void VerifyFooter(byte[] f1, string footer)
    {
        if (string.IsNullOrEmpty(footer))
            return;

        var f2 = GetBytes(footer);
        if (f1.Length != f2.Length || !CryptoBytes.ConstantTimeEquals(f1, f2))
            throw new PasetoInvalidException("Footer is not valid");
    }
}
