namespace Paseto;

/// <summary>
/// Parameters for the Password-Based Key Wrapping (PBKW) PASERK operations
/// (<c>local-pw</c> / <c>secret-pw</c>).
/// </summary>
/// <remarks>
/// The Argon2id parameters (<see cref="MemoryLimitBytes"/>, <see cref="OpsLimit"/>,
/// <see cref="Parallelism"/>) apply to the v2/v4 variants; <see cref="Iterations"/> applies
/// to the PBKDF2-SHA384 v1/v3 variants. Only the parameters relevant to the key's protocol
/// version are used when encoding. See
/// <see href="https://github.com/paseto-standard/paserk/blob/master/operations/PBKW.md">PBKW spec</see>.
/// </remarks>
public sealed class PbkwOptions
{
    /// <summary>
    /// Argon2id memory limit in bytes (v2/v4). Defaults to 64 MiB. Must be a multiple of 1024.
    /// </summary>
    public long MemoryLimitBytes { get; init; } = 67_108_864;

    /// <summary>
    /// Argon2id operations limit / time cost (v2/v4). Defaults to 2.
    /// </summary>
    public int OpsLimit { get; init; } = 2;

    /// <summary>
    /// Argon2id degree of parallelism (v2/v4). Defaults to 1 (matching libsodium's crypto_pwhash).
    /// </summary>
    public int Parallelism { get; init; } = 1;

    /// <summary>
    /// PBKDF2-SHA384 iteration count (v1/v3). Defaults to 100,000.
    /// </summary>
    public int Iterations { get; init; } = 100_000;
}
