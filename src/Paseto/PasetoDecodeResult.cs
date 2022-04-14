namespace Paseto;

using System;

public class PasetoDecodeResult
{
    /// <summary>
    /// Returns a flag indication whether the PASETO token is valid.
    /// </summary>
    /// <value>True if the PASETO token is valid, otherwise false.</value>
    public bool IsValid { get; protected set; }

    /// <summary>
    /// Gets the PASETO token if the operation was successful.
    /// </summary>
    public PasetoToken Paseto { get; protected set; }

    /// <summary>
    /// Gets the Exception if the operation failed.
    /// </summary>
    public Exception Exception { get; protected set; }

    /// <summary>
    /// Returns a <see cref="PasetoDecodeResult"/> that represents a successful PASETO token decode operation.
    /// </summary>
    /// <param name="paseto">A <see cref="PasetoToken"/> with returned token.</param>
    /// <returns>A <see cref="PasetoDecodeResult"/> that represents a successful PASETO token decode operation.</returns>
    public static PasetoDecodeResult Success(PasetoToken paseto)
    {
        var result = new PasetoDecodeResult
        {
            IsValid = true,
            Paseto = paseto
        };
        return result;
    }

    /// <summary>
    /// Returns a <see cref="PasetoDecodeResult"/> that represents a failed PASETO token decode operation.
    /// </summary>
    /// <param name="exception">The <see cref="Exception"/> returned from the decode operation.</param>
    /// <returns>A <see cref="PasetoDecodeResult"/> that represents a failed PASETO token decode operation.</returns>
    public static PasetoDecodeResult Failed(Exception exception)
    {
        var result = new PasetoDecodeResult
        {
            Exception = exception
        };
        return result;
    }

    /// <summary>
    /// Converts the value of the current <see cref="PasetoDecodeResult"/> object to its equivalent string representation.
    /// </summary>
    /// <returns>A string representation of value of the current <see cref="PasetoDecodeResult"/> object.</returns>
    public override string ToString() => IsValid ? "Succeeded" : "Failed";
}