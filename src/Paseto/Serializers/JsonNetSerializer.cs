namespace Paseto.Serializers;

using System.Text.Json;

/// <summary>
/// JSON serializer using System.Text.Json implementation.
/// </summary>
public sealed class JsonNetSerializer : IJsonSerializer
{
    /// <inheritdoc />
    public string Serialize(object obj, JsonSerializerOptions options = null) => JsonSerializer.Serialize(obj, options);

    /// <inheritdoc />
    public T Deserialize<T>(string json, JsonSerializerOptions options = null) => JsonSerializer.Deserialize<T>(json, options);
}
