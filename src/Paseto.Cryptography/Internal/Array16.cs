namespace Paseto.Cryptography.Internal
{
    // Array16<UInt32> Salsa20 state
    // Array16<UInt64> SHA-512 block
    internal struct Array16<T>
    {
        internal T x0;
        internal T x1;
        internal T x2;
        internal T x3;
        internal T x4;
        internal T x5;
        internal T x6;
        internal T x7;
        internal T x8;
        internal T x9;
        internal T x10;
        internal T x11;
        internal T x12;
        internal T x13;
        internal T x14;
        internal T x15;
    }
}
