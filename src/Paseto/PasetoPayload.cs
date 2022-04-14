namespace Paseto;

using System.Collections.Generic;

using Serializers;

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
    public string SerializeToJson() => Serializer.Serialize(this);

    /// <summary>
    /// Deserializes JSON into a <see cref="PasetoPayload"/> instance.
    /// </summary>
    /// <param name="jsonString">The JSON to deserialize.</param>
    /// <returns>An instance of <see cref="PasetoPayload"/>.</returns>
    public PasetoPayload DeserializeFromJson(string jsonString) => Serializer.Deserialize<PasetoPayload>(jsonString);

    internal void SetSerializer(IJsonSerializer serializer) => Serializer = serializer;
}
