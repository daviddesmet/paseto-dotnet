namespace Paseto;

using System.Collections.Generic;

using Paseto.Builder;
using Paseto.Extensions;
using Paseto.Serializers;

/// <summary>
/// The Paseto Payload.
/// </summary>
/// <seealso cref="System.Collections.Generic.Dictionary{string, object}" />
public class PasetoPayload : Dictionary<string, object>
{
    public PasetoPayload(IJsonSerializer serializer = null) => Serializer = serializer ?? new JsonNetSerializer();

    /// <summary>
    /// Gets the Serializer used for serializing and deserializing the payload.
    /// </summary>
    public IJsonSerializer Serializer { get; private set; }

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    public string ToJson() => Serializer.Serialize(this);

    /// <summary>
    /// Deserializes JSON into a <see cref="PasetoPayload"/> instance.
    /// </summary>
    /// <param name="jsonString">The JSON to deserialize.</param>
    /// <returns>An instance of <see cref="PasetoPayload"/>.</returns>
    public PasetoPayload FromJson(string jsonString) => Serializer.Deserialize<PasetoPayload>(jsonString);

    public bool HasAudience() => ContainsKey(RegisteredClaims.Audience.ToDescription());

    public bool HasIssuer() => ContainsKey(RegisteredClaims.Issuer.ToDescription());

    public bool HasIssuedAt() => ContainsKey(RegisteredClaims.IssuedAt.ToDescription());

    public bool HasNotBefore() => ContainsKey(RegisteredClaims.NotBefore.ToDescription());

    public bool HasValidFrom() => ContainsKey(RegisteredClaims.NotBefore.ToDescription());

    public bool HasExpiration() => ContainsKey(RegisteredClaims.ExpirationTime.ToDescription());

    public bool HasValidTo() => ContainsKey(RegisteredClaims.ExpirationTime.ToDescription());

    public bool HasSubject() => ContainsKey(RegisteredClaims.Subject.ToDescription());

    public bool HasTokenIdentifier() => ContainsKey(RegisteredClaims.TokenIdentifier.ToDescription());

    internal void SetSerializer(IJsonSerializer serializer) => Serializer = serializer;
}
