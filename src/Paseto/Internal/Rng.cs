namespace Paseto.Internal;

using System.Security.Cryptography;

/// <summary>
/// Cryptographically secure random byte generation that works uniformly across target frameworks.
/// <para>
/// The static <see cref="RandomNumberGenerator"/> convenience methods (<c>Fill</c>, <c>GetBytes</c>)
/// were introduced in .NET Core / .NET 6+ and do not exist on .NET Framework. On .NET Framework a
/// shared instance from <see cref="RandomNumberGenerator.Create()"/> is used, which is equally a
/// CSPRNG and is thread-safe.
/// </para>
/// </summary>
internal static class Rng
{
#if NETFRAMEWORK
    private static readonly RandomNumberGenerator Instance = RandomNumberGenerator.Create();
#endif

    /// <summary>Fills <paramref name="data"/> with cryptographically strong random bytes.</summary>
    internal static void Fill(byte[] data)
    {
#if NETFRAMEWORK
        Instance.GetBytes(data);
#else
        RandomNumberGenerator.Fill(data);
#endif
    }

    /// <summary>Returns a new array of <paramref name="count"/> cryptographically strong random bytes.</summary>
    internal static byte[] GetBytes(int count)
    {
#if NETFRAMEWORK
        var data = new byte[count];
        Instance.GetBytes(data);
        return data;
#else
        return RandomNumberGenerator.GetBytes(count);
#endif
    }
}
