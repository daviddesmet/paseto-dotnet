using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Paseto.Cryptography;

internal static class Pbkdf2
{
    internal static byte[] Sha384(byte[] password, byte[] salt, int iterations)
    {
        var pdb = new Pkcs5S2ParametersGenerator(new Sha384Digest());
        pdb.Init(password, salt, iterations);
        var key = (KeyParameter)pdb.GenerateDerivedMacParameters(384 * 8);
        return key.GetKey();
    }
}