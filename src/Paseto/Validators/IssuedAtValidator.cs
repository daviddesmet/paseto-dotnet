namespace Paseto.Validators;

using System;
using Paseto.Validators.Internal;

/// <summary>
/// The NotAfter Validator. This class cannot be inherited.
/// </summary>
/// <seealso cref="Paseto.Validators.BaseValidator" />
public sealed class IssuedAtValidator : BaseValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IssuedAtValidator"/> class.
    /// </summary>
    /// <param name="payload">The payload.</param>
    public IssuedAtValidator(PasetoPayload payload) : base(payload) { }

    /// <summary>
    /// Gets the name of the claim.
    /// </summary>
    /// <value>The name of the claim.</value>
    public override string ClaimName => PasetoRegisteredClaimNames.IssuedAt;

    /// <summary>
    /// Validates the payload against the provided optional expected value. Throws an exception if not valid.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    /// <exception cref="PasetoTokenValidationException">
    /// Token is not yet valid.
    /// </exception>
    public override void Validate(IComparable expected = null)
    {
        if (!Payload.TryGetValue(ClaimName, out var value))
            throw new PasetoTokenValidationException($"Claim '{ClaimName}' not found");

        DateTime iat;
        try
        {
            iat = Convert.ToDateTime(value);
        }
        catch (Exception)
        {
            throw new PasetoTokenValidationException($"Claim '{ClaimName}' must be a DateTime");
        }

        expected ??= DateTime.UtcNow;

        if (Comparer.GetComparisonResult(iat, expected) > 0) // expected >= iat
            throw new PasetoTokenValidationException("Token is not yet valid");
    }

    /// <summary>
    /// Validates the payload against the provided optional expected value.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    /// <returns><c>true</c> if the specified value is valid; otherwise, <c>false</c>.</returns>
    public override bool IsValid(IComparable expected = null)
    {
        try
        {
            Validate(expected);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}