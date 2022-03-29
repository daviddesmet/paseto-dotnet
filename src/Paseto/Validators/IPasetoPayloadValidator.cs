namespace Paseto.Validators;

using System;

/// <summary>
/// Defines a Paseto Payload Validator.
/// </summary>
public interface IPasetoPayloadValidator
{
    /// <summary>
    /// Gets the name of the claim.
    /// </summary>
    /// <value>The name of the claim.</value>
    string ClaimName { get; }

    /// <summary>
    /// Validates the payload against the provided optional expected value. Throws an exception if not valid.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    void Validate(IComparable expected = null);

    /// <summary>
    /// Validates the payload against the provided optional expected value.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    /// <returns><c>true</c> if the specified value is valid; otherwise, <c>false</c>.</returns>
    bool IsValid(IComparable expected = null);
}
