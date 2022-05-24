namespace Paseto.Handlers;

using System;
using Paseto.Cryptography.Key;
using Paseto.Protocol;
using Paseto.Validators;

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

    public virtual PasetoTokenValidationResult ValidateTokenPayload(PasetoToken token, PasetoTokenValidationParameters validationParameters)
    {
        if (token is null)
            return PasetoTokenValidationResult.Failed(new ArgumentNullException(nameof(token)));

        if (validationParameters is null)
            return PasetoTokenValidationResult.Failed(new ArgumentNullException(nameof(validationParameters)));

        try
        {
            ValidateLifetime(token, validationParameters);
            ValidateAudience(token, validationParameters);
            ValidateIssuer(token, validationParameters);
            ValidateSubject(token, validationParameters);
        }
        catch (Exception ex)
        {
            return PasetoTokenValidationResult.Failed(ex);
        }

        return PasetoTokenValidationResult.Success(token);
    }

    protected virtual void ValidateLifetime(PasetoToken token, PasetoTokenValidationParameters validationParameters)
    {
        if (!validationParameters.ValidateLifetime)
            return;

        if (token.Payload.HasValidTo())
            new ExpirationTimeValidator(token.Payload).Validate();

        if (token.Payload.HasValidFrom())
            new NotBeforeValidator(token.Payload).Validate();

        if (token.Payload.HasIssuedAt())
            new IssuedAtValidator(token.Payload).Validate();
    }

    protected virtual void ValidateAudience(PasetoToken token, PasetoTokenValidationParameters validationParameters)
    {
        if (!validationParameters.ValidateAudience)
            return;

        if (token.Payload.HasAudience())
            new EqualValidator(token.Payload, PasetoRegisteredClaimNames.Audience).Validate(validationParameters.ValidAudience);
    }

    protected virtual void ValidateIssuer(PasetoToken token, PasetoTokenValidationParameters validationParameters)
    {
        if (!validationParameters.ValidateIssuer)
            return;

        if (token.Payload.HasIssuer())
            new EqualValidator(token.Payload, PasetoRegisteredClaimNames.Issuer).Validate(validationParameters.ValidIssuer);
    }

    protected virtual void ValidateSubject(PasetoToken token, PasetoTokenValidationParameters validationParameters)
    {
        if (!validationParameters.ValidateSubject)
            return;

        if (token.Payload.HasSubject())
            new EqualValidator(token.Payload, PasetoRegisteredClaimNames.Subject).Validate(validationParameters.ValidSubject);
    }
}
