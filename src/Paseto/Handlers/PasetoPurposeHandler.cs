namespace Paseto.Handlers;

using System;
using Paseto.Cryptography.Key;
using Paseto.Protocol;

/// <summary>
/// Abstract Paseto Purpose Handler.
/// </summary>
public abstract class PasetoPurposeHandler
{
    protected PasetoPurposeHandler(PasetoKey pasetoKey) => PasetoKey = pasetoKey ?? throw new ArgumentNullException(nameof(pasetoKey));

    /// <summary>
    /// Gets the Purpose.
    /// </summary>
    public abstract Purpose Purpose { get; }

    /// <summary>
    /// Gets the Paseto Key.
    /// </summary>
    protected PasetoKey PasetoKey { get; }

    /// <summary>
    /// Validates the Protocol Version against the Paseto Key.
    /// </summary>
    /// <param name="protocol">The protocol version.</param>
    /// <exception cref="PasetoInvalidException"></exception>
    public void Validate(IPasetoProtocolVersion protocol)
    {
        if (!PasetoKey.IsValidFor(protocol, Purpose))
            throw new PasetoInvalidException($"Key is not valid for {Purpose} purpose and {protocol.Version} version");
    }
}
