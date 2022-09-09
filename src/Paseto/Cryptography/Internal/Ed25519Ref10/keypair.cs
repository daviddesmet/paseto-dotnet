namespace Paseto.Cryptography.Internal.Ed25519Ref10;

using System;
using Paseto.Extensions;

internal static partial class Ed25519Operations
{
    internal static void crypto_sign_keypair(Span<byte> pk, int pkoffset, Span<byte> sk, int skoffset, ReadOnlySpan<byte> seed, int seedoffset)
    {
        GroupElementP3 A;
        int i;
        Span<byte> h = stackalloc byte[64];

        SpanExtensions.Copy(seed, seedoffset, sk, skoffset, 32);

        var hasher = new Sha512();
        hasher.Update(sk, skoffset, 32);
        hasher.Finish(h);

        ScalarOperations.sc_clamp(h, 0);

        GroupOperations.ge_scalarmult_base(out A, h, 0);
        GroupOperations.ge_p3_tobytes(pk, pkoffset, ref A);

        SpanExtensions.Copy(pk, pkoffset, sk, skoffset+32, 32);
        CryptoBytesExtensions.Wipe(h);
    }
}
