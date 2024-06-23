namespace Paseto.Validators;

using System;
using System.Text.Json;
using Paseto.Validators.Internal;

/// <summary>
/// The Base Date Validator.
/// </summary>
/// <seealso cref="IPasetoPayloadValidator" />
public abstract class DateValidator : BaseValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DateValidator"/> class.
    /// </summary>
    /// <param name="payload">The payload.</param>
    public DateValidator(PasetoPayload payload) : base(payload) { }

    /// <summary>
    /// Validates the input value against the provided optional expected value. Throws an exception if not valid.
    /// </summary>
    /// <param name="value">The input value to validate.</param>
    /// <param name="expected">The optional expected value.</param>
    public abstract void ValidateDate(IComparable value, IComparable expected = null);

    /// <summary>
    /// Validates the payload against the provided optional expected value. Throws an exception if not valid.
    /// </summary>
    /// <param name="expected">The optional expected value.</param>
    /// <exception cref="PasetoTokenValidationException">
    /// Token has expired.
    /// </exception>
    public override void Validate(IComparable expected = null)
    {
        if (!Payload.TryGetValue(ClaimName, out var value))
            throw new PasetoTokenValidationException($"Claim '{ClaimName}' not found");

        DateTime exp;
        try
        {
            if (value is JsonElement json)
                value = GetValueFromJsonElement(json);

            if (value is string s)
                exp = DateTimeOffset.Parse(s).UtcDateTime;
            else
                exp = Convert.ToDateTime(value);
        }
        catch (Exception)
        {
            throw new PasetoTokenValidationException($"Claim '{ClaimName}' must be a DateTime");
        }

        expected ??= DateTime.UtcNow;

        ValidateDate(exp, expected);
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