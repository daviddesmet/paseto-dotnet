namespace Paseto;

/// <summary>
/// Upper bounds on the work factors accepted when unwrapping a PASERK <c>local-pw</c> /
/// <c>secret-pw</c> key.
/// </summary>
/// <remarks>
/// The PBKW cost parameters are stored inside the PASERK and the KDF must run before the
/// authentication tag can be verified, so an untrusted PASERK could otherwise force arbitrary
/// memory and CPU usage. Parameters above these limits are rejected before the KDF runs.
/// Raise them only if you need to unwrap keys produced with higher work factors.
/// </remarks>
public sealed class PbkwLimits
{
    /// <summary>
    /// The default limits.
    /// </summary>
    public static PbkwLimits Default { get; } = new();

    /// <summary>
    /// Maximum Argon2id memory limit in bytes (v2/v4). Defaults to 256 MiB.
    /// </summary>
    public long MaxMemoryLimitBytes { get; init; } = 268_435_456;

    /// <summary>
    /// Maximum Argon2id operations limit / time cost (v2/v4). Defaults to 4.
    /// </summary>
    public int MaxOpsLimit { get; init; } = 4;

    /// <summary>
    /// Maximum Argon2id degree of parallelism (v2/v4). Defaults to 4.
    /// </summary>
    public int MaxParallelism { get; init; } = 4;

    /// <summary>
    /// Maximum PBKDF2-SHA384 iteration count (v1/v3). Defaults to 1,000,000.
    /// </summary>
    public int MaxIterations { get; init; } = 1_000_000;
}
