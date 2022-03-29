namespace Paseto.Cryptography.Internal.Ed25519Ref10;

internal static partial class FieldOperations
{

    /*
	h = f * 121666
	Can overlap h with f.

	Preconditions:
	   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

	Postconditions:
	   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	*/

    public static void fe_mul121666(out FieldElement h, ref FieldElement f)
    {
        int f0 = f.x0;
        int f1 = f.x1;
        int f2 = f.x2;
        int f3 = f.x3;
        int f4 = f.x4;
        int f5 = f.x5;
        int f6 = f.x6;
        int f7 = f.x7;
        int f8 = f.x8;
        int f9 = f.x9;
        long h0 = f0 * (long)121666;
        long h1 = f1 * (long)121666;
        long h2 = f2 * (long)121666;
        long h3 = f3 * (long)121666;
        long h4 = f4 * (long)121666;
        long h5 = f5 * (long)121666;
        long h6 = f6 * (long)121666;
        long h7 = f7 * (long)121666;
        long h8 = f8 * (long)121666;
        long h9 = f9 * (long)121666;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        carry9 = (h9 + (long)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        carry1 = (h1 + (long)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry3 = (h3 + (long)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry5 = (h5 + (long)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        carry7 = (h7 + (long)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry0 = (h0 + (long)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry2 = (h2 + (long)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry4 = (h4 + (long)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry6 = (h6 + (long)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        carry8 = (h8 + (long)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }
}
