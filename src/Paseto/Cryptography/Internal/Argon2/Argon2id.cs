﻿using Paseto.Cryptography.Internal.Argon2;

namespace Paseto.Cryptography.Internal.Argon2;

/// <summary>
/// An implementation of Argon2 https://github.com/P-H-C/phc-winner-argon2
/// </summary>
internal sealed class Argon2id : Argon2
{
    /// <summary>
    /// Create an Argon2 for encrypting the given password using Argon2id
    /// </summary>
    /// <param name="password"></param>
    public Argon2id(byte[] password)
        : base(password)
    {
    }

    internal override Argon2Core BuildCore(int bc)
    {
        return new Argon2idCore(bc);
    }

}