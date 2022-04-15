namespace Paseto.Cryptography.Internal.Ed25519Ref10;

internal static partial class GroupOperations
{
    internal static void ge_p3_tobytes(byte[] s, int offset, ref GroupElementP3 h)
    {
        FieldOperations.fe_invert(out FieldElement recip, ref h.Z);
        FieldOperations.fe_mul(out FieldElement x, ref h.X, ref recip);
        FieldOperations.fe_mul(out FieldElement y, ref h.Y, ref recip);
        FieldOperations.fe_tobytes(s, offset, ref y);
        s[offset + 31] ^= (byte)(FieldOperations.fe_isnegative(ref x) << 7);
    }
}
