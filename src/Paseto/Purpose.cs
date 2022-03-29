namespace Paseto;

using System.ComponentModel;

/// <summary>
/// The Purpose of the Paseto.
/// </summary>
public enum Purpose
{
    /// <summary>
    /// Shared-key encryption (symmetric-key, AEAD).
    /// </summary>
    [Description("local")]
    Local,

    /// <summary>
    /// Public-key digital signatures (asymmetric-key).
    /// </summary>
    [Description("public")]
    Public
}
