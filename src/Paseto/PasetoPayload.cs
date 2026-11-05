namespace Paseto;

using System;
using System.Collections.Generic;
using System.Text.Json;

using Paseto.Builder;
using Paseto.Extensions;
using Paseto.Serializers;

/// <summary>
/// The Paseto Payload.
/// </summary>
/// <seealso cref="System.Collections.Generic.Dictionary{string, object}" />
public class PasetoPayload : Dictionary<string, object>
{
    private IJsonSerializer _serializer;

    public PasetoPayload() => _serializer = new JsonNetSerializer();

    public PasetoPayload(IJsonSerializer serializer = null) => _serializer = serializer ?? new JsonNetSerializer();

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public string ToJson() => _serializer.Serialize(this);

    /// <summary>
    /// Deserializes JSON into a <see cref="PasetoPayload"/> instance.
    /// </summary>
    /// <param name="jsonString">The JSON to deserialize.</param>
    /// <returns>An instance of <see cref="PasetoPayload"/>.</returns>
    public PasetoPayload FromJson(string jsonString) => _serializer.Deserialize<PasetoPayload>(jsonString);

    public bool HasAudience() => ContainsKey(RegisteredClaims.Audience.ToDescription());

    public bool HasIssuer() => ContainsKey(RegisteredClaims.Issuer.ToDescription());

    public bool HasIssuedAt() => ContainsKey(RegisteredClaims.IssuedAt.ToDescription());

    public bool HasNotBefore() => ContainsKey(RegisteredClaims.NotBefore.ToDescription());

    public bool HasValidFrom() => ContainsKey(RegisteredClaims.NotBefore.ToDescription());

    public bool HasExpiration() => ContainsKey(RegisteredClaims.ExpirationTime.ToDescription());

    public bool HasValidTo() => ContainsKey(RegisteredClaims.ExpirationTime.ToDescription());

    public bool HasSubject() => ContainsKey(RegisteredClaims.Subject.ToDescription());

    public bool HasTokenIdentifier() => ContainsKey(RegisteredClaims.TokenIdentifier.ToDescription());

    /// <summary>
    /// Gets a claim converted to <typeparamref name="T"/>.
    /// </summary>
    /// <remarks>
    /// Decoded claim values are <see cref="JsonElement"/>s; values added before encoding keep their .NET type.
    /// Both are handled: a value that already is a <typeparamref name="T"/> is returned as is, otherwise it is
    /// converted through the payload's JSON serializer (e.g. an ISO 8601 string to <see cref="DateTime"/>).
    /// </remarks>
    /// <typeparam name="T">The type to convert the claim value to.</typeparam>
    /// <param name="name">The claim name.</param>
    /// <param name="options">Optional serializer options used for the conversion.</param>
    /// <returns>The claim value as <typeparamref name="T"/>.</returns>
    /// <exception cref="KeyNotFoundException">The claim does not exist.</exception>
    /// <exception cref="JsonException">The claim value cannot be converted to <typeparamref name="T"/>.</exception>
    public T GetClaim<T>(string name, JsonSerializerOptions options = null)
    {
        if (!TryGetValue(name, out var value))
            throw new KeyNotFoundException($"The claim '{name}' does not exist.");

        return ConvertClaim<T>(value, options);
    }

    /// <summary>
    /// Tries to get a claim converted to <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The type to convert the claim value to.</typeparam>
    /// <param name="name">The claim name.</param>
    /// <param name="value">The claim value, or the default of <typeparamref name="T"/> when it is missing or cannot be converted.</param>
    /// <param name="options">Optional serializer options used for the conversion.</param>
    /// <returns><c>true</c> if the claim exists and could be converted; otherwise, <c>false</c>.</returns>
    public bool TryGetClaim<T>(string name, out T value, JsonSerializerOptions options = null)
    {
        value = default;
        if (!TryGetValue(name, out var raw))
            return false;

        try
        {
            value = ConvertClaim<T>(raw, options);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    internal T Deserialize<T>(string json, JsonSerializerOptions options = null) => _serializer.Deserialize<T>(json, options);

    private T ConvertClaim<T>(object value, JsonSerializerOptions options) => value switch
    {
        T typed => typed,
        null => default,
        JsonElement element => _serializer.Deserialize<T>(element.GetRawText(), options),
        _ => _serializer.Deserialize<T>(_serializer.Serialize(value, options), options),
    };

    internal void SetSerializer(IJsonSerializer serializer) => _serializer = serializer;
}
