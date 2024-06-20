namespace Paseto.Serializers;

using System.Text.Json;

/// <summary>
/// Provides JSON Serialize and Deserialize.  Allows custom serializers used.
/// </summary>
public interface IJsonSerializer
{
    /// <summary>
    /// Serialize an object to JSON string
    /// </summary>
    /// <param name="obj">The object to serialize</param>
    /// <param name="options">Provides options to use with <see cref="JsonSerializer" /></param>
    /// <returns>JSON string</returns>
    string Serialize(object obj, JsonSerializerOptions options = null);

    /// <summary>
    /// Deserialize a JSON string to typed object.
    /// </summary>
    /// <typeparam name="T">The type of object</typeparam>
    /// <param name="json">The JSON string</param>
    /// <param name="options">Provides options to use with <see cref="JsonSerializer" /></param>
    /// <returns>A typed object</returns>
    T Deserialize<T>(string json, JsonSerializerOptions options = null);
}
