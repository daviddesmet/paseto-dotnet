namespace Paseto.Validators
{
    using System;

    using Builder;
    using Extensions;
    using Internal;

    /// <summary>
    /// The NotBefore Validator. This class cannot be inherited.
    /// </summary>
    /// <seealso cref="Paseto.Validation.BaseValidator" />
    public sealed class NotBeforeValidator : BaseValidator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NotBeforeValidator"/> class.
        /// </summary>
        /// <param name="payload">The payload.</param>
        public NotBeforeValidator(PasetoPayload payload) : base(payload) { }

        /// <summary>
        /// Gets the name of the claim.
        /// </summary>
        /// <value>The name of the claim.</value>
        public override string ClaimName => RegisteredClaims.NotBefore.GetRegisteredClaimName();

        /// <summary>
        /// Validates the payload against the provided optional expected value. Throws an exception if not valid.
        /// </summary>
        /// <param name="expected">The optional expected value.</param>
        /// <exception cref="TokenValidationException">
        /// Token is not yet valid.
        /// </exception>
        public override void Validate(IComparable expected)
        {
            if (!Payload.TryGetValue(ClaimName, out var value))
                throw new TokenValidationException($"Claim '{ClaimName}' not found.");

            DateTime nbf;
            try
            {
                nbf = Convert.ToDateTime(value);
            }
            catch (Exception)
            {
                throw new TokenValidationException($"Claim '{ClaimName}' must be a DateTime.");
            }

            if (expected is null)
                expected = DateTime.UtcNow;

            if (Comparer.GetComparisonResult(nbf, expected) >= 0) // expected < nbf
                throw new TokenValidationException("Token is not yet valid.");
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
}
