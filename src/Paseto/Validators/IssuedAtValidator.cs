namespace Paseto.Validators;

using System;
using Paseto.Validators.Internal;

/// <summary>
/// The NotAfter Validator. This class cannot be inherited.
/// </summary>
/// <seealso cref="Paseto.Validators.DateValidator" />
public sealed class IssuedAtValidator : DateValidator
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

    /// <inheritdoc />
    public override void ValidateDate(IComparable value, IComparable expected = null)
    {
        if (Comparer.GetComparisonResult(value, expected) > 0) // expected >= iat
            throw new PasetoTokenValidationException("Token is not yet valid");
    }
}