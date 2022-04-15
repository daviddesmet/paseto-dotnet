namespace Paseto;

public class PasetoTokenValidationParameters
{
    /// <summary>
    /// Gets or sets a value for comparing the lifetime of the payload.
    /// </summary>
    /// <remarks>
    /// The current time should be less than or equal to the DateTime stored in the exp claim.
    /// The current time should be greater than or equal to the DateTime stored in the iat claim.
    /// The current time should be greater than or equal to the DateTime stored in the nbf claim.
    /// </remarks>
    public bool ValidateLifetime { get; set; }

    /// <summary>
    /// Gets or sets a value for comparing the audience of the payload.
    /// </summary>
    public bool ValidateAudience { get; set; }

    /// <summary>
    /// Gets or sets a value for comparing the issuer of the payload.
    /// </summary>
    public bool ValidateIssuer { get; set; }

    /// <summary>
    /// Gets or sets the valid audience for comparing against the payload-provided aud.
    /// </summary>
    public string ValidAudience { get; set; }

    /// <summary>
    /// Gets or sets the valid issuer for comparing against the payload-provided iss.
    /// </summary>
    public string ValidIssuer { get; set; }
}