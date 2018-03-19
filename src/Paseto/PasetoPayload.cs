namespace Paseto
{
    using System;
    using System.Collections.Generic;

    using Serializers;

    /// <summary>
    /// The Paseto Payload.
    /// </summary>
    /// <seealso cref="System.Collections.Generic.Dictionary{System.String, System.Object}" />
    public class PasetoPayload : Dictionary<string, object>
    {
        private IJsonSerializer _serializer = new JsonNetSerializer();

        /// <summary>
        /// Serializes this instance to JSON.
        /// </summary>
        /// <returns>This instance as JSON.</returns>
        public string SerializeToJson() => _serializer.Serialize(this as IDictionary<string, object>);

        /// <summary>
        /// Deserialzes JSON into a <see cref="PasetoPayload"/> instance.
        /// </summary>
        /// <param name="jsonString">The JSON to deserialze.</param>
        /// <returns>An instance of <see cref="PasetoPayload"/>.</returns>
        public static PasetoPayload DeserializeFromJson(string jsonString)=> new JsonNetSerializer().Deserialize<PasetoPayload>(jsonString);
    }
}
