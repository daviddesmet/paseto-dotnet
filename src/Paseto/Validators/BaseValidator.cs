namespace Paseto.Validators;

using System;

/// <summary>
/// The Base Validator.
/// </summary>
/// <seealso cref="Paseto.Validation.IPasetoPayloadValidator" />
public abstract class BaseValidator : IPasetoPayloadValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BaseValidator"/> class.
    /// </summary>
    /// <param name="payload">The payload.</param>
    public BaseValidator(PasetoPayload payload) => Payload = payload;

    /// <summary>
    /// Gets the Paseto payload.
    /// </summary>
    /// <value>The Paseto payload.</value>
    protected PasetoPayload Payload { get; }

    /// <summary>
    /// Gets the name of the claim.
    /// </summary>
    /// <value>The name of the claim.</value>
    public abstract string ClaimName { get; }

    /// <summary>
    /// Validates the payload against the provided optional expected value. Throws an exception if not valid.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    public abstract void Validate(IComparable expected = null);

    /// <summary>
    /// Validates the payload against the provided optional expected value.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    /// <returns><c>true</c> if the specified value is valid; otherwise, <c>false</c>.</returns>
    public abstract bool IsValid(IComparable expected = null);
}
