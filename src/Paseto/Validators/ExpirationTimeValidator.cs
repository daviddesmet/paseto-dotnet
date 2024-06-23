namespace Paseto.Validators;

using System;
using Paseto.Validators.Internal;

/// <summary>
/// The ExpirationTime Validator. This class cannot be inherited.
/// </summary>
/// <seealso cref="Paseto.Validators.DateValidator" />
public sealed class ExpirationTimeValidator : DateValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExpirationTimeValidator"/> class.
    /// </summary>
    /// <param name="payload">The payload.</param>
    public ExpirationTimeValidator(PasetoPayload payload) : base(payload) { }

    /// <summary>
    /// Gets the name of the claim.
    /// </summary>
    /// <value>The name of the claim.</value>
    public override string ClaimName => PasetoRegisteredClaimNames.ExpirationTime;

    /// <inheritdoc />
    public override void ValidateDate(IComparable value, IComparable expected = null)
    {
        if (Comparer.GetComparisonResult(value, expected) < 0) // expected >= exp
            throw new PasetoTokenValidationException("Token has expired");
    }
}
