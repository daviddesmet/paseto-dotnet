namespace Paseto.Cryptography.Internal
{
    // Array8<UInt32> Poly1305 key
    // Array8<UInt64> SHA-512 state/output
    internal struct Array8<T>
    {
        internal T x0;
        internal T x1;
        internal T x2;
        internal T x3;
        internal T x4;
        internal T x5;
        internal T x6;
        internal T x7;
    }
}
