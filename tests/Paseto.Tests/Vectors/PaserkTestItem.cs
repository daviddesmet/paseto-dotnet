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
}