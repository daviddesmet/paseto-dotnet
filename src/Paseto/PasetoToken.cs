namespace Paseto;

using System;
using System.Text.Json;
using Paseto.Extensions;
using static Utils.EncodingHelper;

public class PasetoToken
{
    private const int MAX_SEGMENT_LEN = 4;

    protected PasetoToken() { }

    public PasetoToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        var parts = token.Split(new[] { '.' }, MAX_SEGMENT_LEN + 1);
        if (parts.Length != 3 && parts.Length != 4)
            throw new PasetoInvalidException("The specified token has an invalid number of segments");

        Version = parts[0];
        Purpose = parts[1].FromDescription<Purpose>();
        Payload = new PasetoPayload().FromJson(parts[2]);

        if (parts.Length == 4)
            Footer = GetString(FromBase64Url(parts[3]));

        RawPayload = parts[2];
        RawToken = token;
    }

    public PasetoToken(string token, string payload)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentNullException(nameof(token));

        var parts = token.Split(['.'], MAX_SEGMENT_LEN + 1);
        if (parts.Length != 3 && parts.Length != 4)
            throw new PasetoInvalidException("The specified token has an invalid number of segments");

        Version = parts[0];
        Purpose = parts[1].FromDescription<Purpose>();
        Payload = new PasetoPayload().FromJson(payload);

        if (parts.Length == 4)
            Footer = GetString(FromBase64Url(parts[3]));

        RawPayload = payload;
        RawToken = token;
    }

    public string Version { get; }

    public Purpose Purpose { get; }

    public PasetoPayload Payload { get; }

    public string Footer { get; }

    public string RawPayload { get; }

    public string RawToken { get; }

    /// <summary>
    /// Deserializes the decoded JSON payload into <typeparamref name="T"/>.
    /// </summary>
    /// <remarks>
    /// Property names are matched as configured by <paramref name="options"/>; by default matching is
    /// case-sensitive, so use <c>[JsonPropertyName("exp")]</c> or <see cref="JsonSerializerOptions.PropertyNameCaseInsensitive"/>.
    /// </remarks>
    /// <typeparam name="T">The type to deserialize the payload to.</typeparam>
    /// <param name="options">Optional serializer options.</param>
    /// <returns>The payload as <typeparamref name="T"/>.</returns>
    public T GetPayload<T>(JsonSerializerOptions options = null) => Payload.Deserialize<T>(RawPayload, options);
}
