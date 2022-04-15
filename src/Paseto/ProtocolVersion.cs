namespace Paseto;

using System.ComponentModel;

/// <summary>
/// The Protocol Version of the Paseto.
/// </summary>
public enum ProtocolVersion
{
    /// <summary>
    /// Version 1: NIST Compatibility
    /// </summary>
    [Description("v1")]
    V1 = 1,

    /// <summary>
    /// Version 2: Sodium Original
    /// </summary>
    [Description("v2")]
    V2 = 2,

    /// <summary>
    /// Version 2: NIST Modern
    /// </summary>
    [Description("v3")]
    V3 = 3,

    /// <summary>
    /// Version 2: Sodium Modern
    /// </summary>
    [Description("v4")]
    V4 = 4
}
