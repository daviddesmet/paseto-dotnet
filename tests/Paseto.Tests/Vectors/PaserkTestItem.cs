namespace Paseto.Tests.Vectors;

using System.Diagnostics;
using Newtonsoft.Json;

[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public class PaserkTestItem
{
    private string DebuggerDisplay => Name ?? $"{{{typeof(PaserkTestItem)}}}";

    public string Name { get; set; }

    public string Key { get; set; }

    public string Paserk { get; set; }

    [JsonProperty("expect-fail")]
    public bool ExpectFail { get; set; }

    public string Comment { get; set; }

    // Wrap (local-wrap / secret-wrap / *-pw) vectors: the unwrapped key in hex.
    public string Unwrapped { get; set; }

    // *-pw vectors.
    public string Password { get; set; }

    public PaserkTestOptions Options { get; set; }

    // *-wrap vectors.
    [JsonProperty("wrapping-key")]
    public string WrappingKey { get; set; }
}

public class PaserkTestOptions
{
    // Argon2id (v2/v4).
    public long Memlimit { get; set; }

    public int Opslimit { get; set; }

    // PBKDF2 (v1/v3).
    public int Iterations { get; set; }
}
