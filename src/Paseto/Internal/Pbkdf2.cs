namespace Paseto.Internal;

using System.Security.Cryptography;

/// <summary>
/// PBKDF2 (RFC 2898) key derivation that works uniformly across target frameworks.
/// <para>
/// The static <see cref="Rfc2898DeriveBytes.Pbkdf2(byte[], byte[], int, HashAlgorithmName, int)"/>
/// overload is only available on .NET 6+. On .NET Framework (4.7.2+) the instance API with a
/// <see cref="HashAlgorithmName"/> is used, which produces identical output for the same inputs.
/// </para>
/// </summary>
internal static class Pbkdf2
{
    /// <summary>Derives <paramref name="outputLength"/> bytes using PBKDF2.</summary>
    internal static byte[] DeriveBytes(byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithmName, int outputLength)
    {
#if NETFRAMEWORK
        using var kdf = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithmName);
        return kdf.GetBytes(outputLength);
#else
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithmName, outputLength);
#endif
    }
}
