namespace Paseto;

using System;

public class PasetoTokenValidationResult
{
    /// <summary>
    /// Returns a flag indication whether the PASETO token is valid.
    /// </summary>
    /// <value>True if the PASETO token is valid, otherwise false.</value>
    public bool IsValid { get; protected set; }

    /// <summary>
    /// Gets the PASETO token if the validation operation was successful.
    /// </summary>
    public PasetoToken Paseto { get; protected set; }

    /// <summary>
    /// Gets the Exception if the validation operation failed.
    /// </summary>
    public Exception Exception { get; protected set; }

    /// <summary>
    /// Returns a <see cref="PasetoTokenValidationResult"/> that represents a successful PASETO token validation operation.
    /// </summary>
    /// <param name="paseto">A <see cref="PasetoToken"/> with returned token.</param>
    /// <returns>A <see cref="PasetoTokenValidationResult"/> that represents a successful PASETO token validation operation.</returns>
    public static PasetoTokenValidationResult Success(PasetoToken paseto)
    {
        var result = new PasetoTokenValidationResult
        {
            IsValid = true,
            Paseto = paseto
        };
        return result;
    }

    /// <summary>
    /// Returns a <see cref="PasetoTokenValidationResult"/> that represents a failed PASETO token validation operation.
    /// </summary>
    /// <param name="exception">The <see cref="Exception"/> returned from the validation operation.</param>
    /// <returns>A <see cref="PasetoTokenValidationResult"/> that represents a failed PASETO token validation operation.</returns>
    public static PasetoTokenValidationResult Failed(Exception exception)
    {
        var result = new PasetoTokenValidationResult
        {
            Exception = exception
        };
        return result;
    }

    /// <summary>
    /// Converts the value of the current <see cref="PasetoTokenValidationResult"/> object to its equivalent string representation.
    /// </summary>
    /// <returns>A string representation of value of the current <see cref="PasetoTokenValidationResult"/> object.</returns>
    public override string ToString() => IsValid ? "Succeeded" : "Failed";
}