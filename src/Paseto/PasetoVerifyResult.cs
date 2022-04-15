namespace Paseto;

public class PasetoVerifyResult
{
    /// <summary>
    /// Returns a flag indication whether the PASETO token is valid.
    /// </summary>
    /// <value>True if the PASETO token is valid, otherwise false.</value>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the PASETO payload if the validation was successful.
    /// </summary>
    public string Payload { get; protected set; }

    /// <summary>
    /// Returns a <see cref="PasetoVerifyResult"/> that represents a successful PASETO token validation operation.
    /// </summary>
    /// <param name="payload">A <see cref="string"/> with returned payload.</param>
    /// <returns>A <see cref="PasetoVerifyResult"/> that represents a successful PASETO token validation operation.</returns>
    public static PasetoVerifyResult Success(string payload)
    {
        var result = new PasetoVerifyResult
        {
            IsValid = true,
            Payload = payload
        };
        return result;
    }

    /// <summary>
    /// Returns a <see cref="PasetoVerifyResult"/> that represents a failed PASETO token validation operation.
    /// </summary>
    /// <returns>A <see cref="PasetoVerifyResult"/> that represents a failed PASETO token validation operation.</returns>
    public static PasetoVerifyResult Failed { get; } = new();

    /// <summary>
    /// Converts the value of the current <see cref="PasetoVerifyResult"/> object to its equivalent string representation.
    /// </summary>
    /// <returns>A string representation of value of the current <see cref="PasetoVerifyResult"/> object.</returns>
    public override string ToString() => IsValid ? "Valid" : "Invalid";
}