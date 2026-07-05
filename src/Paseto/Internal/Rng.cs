namespace Paseto.Internal;

using System.Security.Cryptography;

/// <summary>
/// Cryptographically secure random byte generation that works uniformly across target frameworks.
/// <para>
/// The static <see cref="RandomNumberGenerator"/> convenience methods (<c>Fill</c>, <c>GetBytes</c>)
/// were introduced in .NET Core / .NET 6+ and do not exist on .NET Framework. On .NET Framework the
/// instance API (<see cref="RandomNumberGenerator.Create()"/>) is used, which is equally a CSPRNG.
/// </para>
/// </summary>
internal static class Rng
{
    /// <summary>Fills <paramref name="data"/> with cryptographically strong random bytes.</summary>
    internal static void Fill(byte[] data)
    {
#if NETFRAMEWORK
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(data);
#else
        RandomNumberGenerator.Fill(data);
#endif
    }

    /// <summary>Returns a new array of <paramref name="count"/> cryptographically strong random bytes.</summary>
    internal static byte[] GetBytes(int count)
    {
#if NETFRAMEWORK
        var data = new byte[count];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(data);
        return data;
#else
        return RandomNumberGenerator.GetBytes(count);
#endif
    }
}
