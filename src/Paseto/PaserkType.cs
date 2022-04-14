namespace Paseto;

using System.ComponentModel;

/// <summary>
/// The PASERK Types.
/// </summary>
public enum PaserkType
{
    /// <summary>
    /// Unique Identifier for a separate PASERK for local PASETOs.
    /// 
    /// This kind of PASERK serves as a pointer to another PASERK, which is in turn intended for local PASETOs.
    /// Format: k[version].lid.[data]
    /// </summary>
    [Description("lid")]
    Lid,

    /// <summary>
    /// Symmetric key for local tokens.
    /// 
    /// This is a plaintext serialization of a symmetric key for PASETO local tokens.
    /// Format: k[version].local.[data]
    /// </summary>
    [Description("local")]
    Local,

    /// <summary>
    /// Symmetric key wrapped by another symmetric key.
    /// 
    /// This PASERK is a secret key intended for local PASETOs, encrypted with a symmetric wrapping key.
    /// Format: k[version].local-wrap.[prefix].[encrypted key]
    /// </summary>
    [Description("local-wrap")]
    LocalWrap,

    /// <summary>
    /// Symmetric key wrapped using password-based encryption.
    /// 
    /// This PASERK is a key intended for local PASETOs, encrypted with a password.
    /// Format: k[version].local-pw.[data]
    /// </summary>
    [Description("local-pw")]
    LocalPassword,

    /// <summary>
    /// Symmetric key wrapped using asymmetric encryption.
    /// 
    /// This PASERK is a secret key intended for local PASETOs, encrypted with an asymmetric wrapping key.
    /// Format: k[version].seal.[data]
    /// </summary>
    [Description("seal")]
    Seal,

    /// <summary>
    /// Unique Identifier for a separate PASERK for public (Secret Key) PASETOs.
    /// 
    /// This kind of PASERK serves as a pointer to another PASERK, which is in turn intended for public PASETOs.
    /// Format: k[version].sid.[data]
    /// </summary>
    [Description("sid")]
    Sid,

    /// <summary>
    /// Secret key for signing public tokens.
    /// 
    /// This is a plaintext serialization of a secret key for PASETO public tokens.
    /// Format: k[version].secret.[data]
    /// </summary>
    [Description("secret")]
    Secret,

    /// <summary>
    /// Asymmetric secret key wrapped by another symmetric key.
    /// 
    /// This PASERK is a secret key intended for public PASETOs, encrypted with a symmetric wrapping key.
    /// Format: k[version].local-wrap.[prefix].[encrypted key]
    /// </summary>
    [Description("secret-wrap")]
    SecretWrap,

    /// <summary>
    /// Asymmetric secret key wrapped using password-based encryption.
    /// 
    /// This PASERK is a secret key intended for public PASETOs, encrypted with a password.
    /// Format: k[version].secret-pw.[data]
    /// </summary>
    [Description("secret-pw")]
    SecretPassword,

    /// <summary>
    /// Unique Identifier for a separate PASERK for public (Public Key) PASETOs.
    /// 
    /// This kind of PASERK serves as a pointer to another PASERK, which is in turn intended for public PASETOs.
    /// Format: k[version].pid.[data]
    /// </summary>
    [Description("pid")]
    Pid,

    /// <summary>
    /// Public key for verifying public tokens.
    /// 
    /// This is a plaintext serialization of a public key for PASETO public tokens.
    /// Format: k[version].public.[data]
    /// </summary>
    [Description("public")]
    Public
}
