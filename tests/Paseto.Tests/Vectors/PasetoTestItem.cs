namespace Paseto.Tests.Vectors;

using System.Diagnostics;
using Newtonsoft.Json;

[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public class PasetoTestItem
{
    private string DebuggerDisplay => Name ?? $"{{{typeof(PasetoTestItem)}}}";

    public string Name { get; set; }

    [JsonProperty("expect-fail")]
    public bool ExpectFail { get; set; }

    public string Nonce { get; set; }

    public string Key { get; set; }

    [JsonProperty("public-key")]
    public string PublicKey { get; set; }

    [JsonProperty("secret-key")]
    public string SecretKey { get; set; }

    [JsonProperty("secret-key-seed")]
    public string SecretKeySeed { get; set; }

    [JsonProperty("secret-key-pem")]
    public string SecretKeyPem { get; set; }

    [JsonProperty("public-key-pem")]
    public string PublicKeyPem { get; set; }

    public string Token { get; set; }

    public string Payload { get; set; }

    public string Footer { get; set; }

    [JsonProperty("implicit-assertion")]
    public string ImplicitAssertion { get; set; }

    public bool IsLocal => Token.Contains(".local.");

    public bool IsPublic => Token.Contains(".public.");
}
