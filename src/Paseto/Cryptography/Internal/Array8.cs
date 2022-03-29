namespace Paseto.Cryptography.Internal
{
    // Array8<uint> Poly1305 key
    // Array8<ulong> SHA-512 state/output
    public struct Array8<T>
    {
        public T x0;
        public T x1;
        public T x2;
        public T x3;
        public T x4;
        public T x5;
        public T x6;
        public T x7;
    }
}
