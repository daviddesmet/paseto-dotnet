namespace Paseto.Cryptography.Internal.Ed25519Ref10;

internal static partial class FieldOperations
{
    /*
	h = -f

	Preconditions:
	   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

	Postconditions:
	   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	*/
    internal static void fe_neg(out FieldElement h, ref FieldElement f)
    {
        var f0 = f.x0;
        var f1 = f.x1;
        var f2 = f.x2;
        var f3 = f.x3;
        var f4 = f.x4;
        var f5 = f.x5;
        var f6 = f.x6;
        var f7 = f.x7;
        var f8 = f.x8;
        var f9 = f.x9;
        var h0 = -f0;
        var h1 = -f1;
        var h2 = -f2;
        var h3 = -f3;
        var h4 = -f4;
        var h5 = -f5;
        var h6 = -f6;
        var h7 = -f7;
        var h8 = -f8;
        var h9 = -f9;
        h.x0 = h0;
        h.x1 = h1;
        h.x2 = h2;
        h.x3 = h3;
        h.x4 = h4;
        h.x5 = h5;
        h.x6 = h6;
        h.x7 = h7;
        h.x8 = h8;
        h.x9 = h9;
    }
}
