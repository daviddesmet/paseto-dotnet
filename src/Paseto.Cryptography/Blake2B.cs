namespace Paseto.Cryptography
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;

    public partial class Blake2B : HashAlgorithm //, IDisposable
    {
        // enum blake2b_constant's
        public const int BLAKE2B_BLOCKBYTES = 128;
        public const int BLAKE2B_BLOCKUINT64S = BLAKE2B_BLOCKBYTES / 8;
        public const int BLAKE2B_OUTBYTES = 64;
        public const int BLAKE2B_KEYBYTES = 64;
        public const int BLAKE2B_SALTBYTES = 16;
        public const int BLAKE2B_PERSONALBYTES = 16;

        public const int ROUNDS = 12;

        //public const ulong IV0 = 0x6A09E667F3BCC908UL;
        //public const ulong IV1 = 0xBB67AE8584CAA73BUL;
        //public const ulong IV2 = 0x3C6EF372FE94F82BUL;
        //public const ulong IV3 = 0xA54FF53A5F1D36F1UL;
        //public const ulong IV4 = 0x510E527FADE682D1UL;
        //public const ulong IV5 = 0x9B05688C2B3E6C1FUL;
        //public const ulong IV6 = 0x1F83D9ABFB41BD6BUL;
        //public const ulong IV7 = 0x5BE0CD19137E2179UL;

        private readonly int _hashSize = 512;

        private bool _isInitialized = false;

        private int _bufferFilled;
        private byte[] _buffer = new byte[BLAKE2B_BLOCKBYTES];
        private ulong[] _state = new ulong[8];
        private ulong[] _m = new ulong[16];
        private ulong _counter0;
        private ulong _counter1;
        private ulong _f0;
        private ulong _f1;

        private ulong[] _rawConfig;

        public Blake2B()
        {
            _fanOut = 1;
            _maxHeight = 1;
            // leafSize = 0;
            // intermediateHashSize = 0;
        }

        public Blake2B(int hashSizeInBits) : this()
        {
            if (hashSizeInBits < 8) // || hashSizeInBits > 512)
                throw new ArgumentOutOfRangeException("hashSizeInBits");

            if (hashSizeInBits % 8 != 0)
                throw new ArgumentOutOfRangeException("hashSizeInBits", "MUST be a multiple of 8");

            _hashSize = hashSizeInBits;
        }

        public override int HashSize => _hashSize;

        public int HashSizeInBytes => _hashSize / 8;

        public int HashSizeInUInt64 => HashSizeInBytes / 4;

        public static readonly ulong[] IV = new ulong[]
        {
            0x6A09E667F3BCC908UL,
            0xBB67AE8584CAA73BUL,
            0x3C6EF372FE94F82BUL,
            0xA54FF53A5F1D36F1UL,
            0x510E527FADE682D1UL,
            0x9B05688C2B3E6C1FUL,
            0x1F83D9ABFB41BD6BUL,
            0x5BE0CD19137E2179UL
        };

        public static readonly int[] Sigma = new int[ROUNDS * 16]
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
        };

        public static ulong BytesToUInt64(byte[] buf, int offset)
        {
            return
                ((ulong)buf[offset + 7] << 7 * 8 |
                ((ulong)buf[offset + 6] << 6 * 8) |
                ((ulong)buf[offset + 5] << 5 * 8) |
                ((ulong)buf[offset + 4] << 4 * 8) |
                ((ulong)buf[offset + 3] << 3 * 8) |
                ((ulong)buf[offset + 2] << 2 * 8) |
                ((ulong)buf[offset + 1] << 1 * 8) |
                ((ulong)buf[offset]));
        }

        public static void UInt64ToBytes(ulong value, byte[] buf, int offset)
        {
            buf[offset + 7] = (byte)(value >> 7 * 8);
            buf[offset + 6] = (byte)(value >> 6 * 8);
            buf[offset + 5] = (byte)(value >> 5 * 8);
            buf[offset + 4] = (byte)(value >> 4 * 8);
            buf[offset + 3] = (byte)(value >> 3 * 8);
            buf[offset + 2] = (byte)(value >> 2 * 8);
            buf[offset + 1] = (byte)(value >> 1 * 8);
            buf[offset] = (byte)value;
        }

        public virtual ulong[] Prepare()
        {
            var c = new ulong[8];

            // digest length
            c[0] |= (ulong)HashSizeInBytes;

            // Key length
            if (Key != null)
            {
                if (Key.Length > BLAKE2B_KEYBYTES)
                    throw new ArgumentException("Key", "Key too long");

                c[0] |= ((ulong)Key.Length << 8);
            }

            if (IntermediateHashSize > 64)
                throw new ArgumentOutOfRangeException("IntermediateHashSize");

            // bool isSequential = TreeConfig == null;
            // FanOut
            c[0] |= FanOut << 16;
            // Depth
            c[0] |= MaxHeight << 24;
            // Leaf length
            c[0] |= LeafSize << 32;
            // Inner length
            c[2] |= IntermediateHashSize << 8;

            // Salt
            if (Salt != null)
            {
                if (Salt.Length != BLAKE2B_SALTBYTES)
                    throw new ArgumentException("Salt has invalid length");

                c[4] = BytesToUInt64(Salt, 0);
                c[5] = BytesToUInt64(Salt, 8);
            }
            // Personalization
            if (Personalization != null)
            {
                if (Personalization.Length != BLAKE2B_PERSONALBYTES)
                    throw new ArgumentException("Personalization has invalid length");

                c[6] = BytesToUInt64(Personalization, 0);
                c[7] = BytesToUInt64(Personalization, 8);
            }

            return c;
        }

        public override void Initialize()
        {
            if (_rawConfig == null)
                _rawConfig = Prepare();

            Initialize(_rawConfig);
        }

        /* public static void ConfigBSetNode(ulong[] rawConfig, byte depth, ulong nodeOffset)
		{
			rawConfig[1] = nodeOffset;
			rawConfig[2] = (rawConfig[2] & ~0xFFul) | depth;
		} */

        public virtual void Initialize(ulong[] c)
        {
            if (c == null)
                throw new ArgumentNullException("config");
            if (c.Length != 8)
                throw new ArgumentException("config length must be 8 words");

            HashClear();

            //_state[0] = IV0;
            //_state[1] = IV1;
            //_state[2] = IV2;
            //_state[3] = IV3;
            //_state[4] = IV4;
            //_state[5] = IV5;
            //_state[6] = IV6;
            //_state[7] = IV7;

            _state[0] = IV[0];
            _state[1] = IV[1];
            _state[2] = IV[2];
            _state[3] = IV[3];
            _state[4] = IV[4];
            _state[5] = IV[5];
            _state[6] = IV[6];
            _state[7] = IV[7];

            for (var i = 0; i < 8; i++)
                _state[i] ^= c[i];

            _isInitialized = true;

            if (Key != null)
                HashCore(Key, 0, Key.Length);
        }

        // public void Dispose() { Dispose(true); }

        protected override void Dispose(bool disposing) { if (disposing) HashClear(); base.Dispose(disposing); }

        public virtual void HashClear()
        {
            _isInitialized = false;

            _counter0 = 0UL;
            _counter1 = 0UL;
            _f0 = 0UL;
            _f1 = 0UL;

            _bufferFilled = 0;
            int i;
            for (i = 0; i < BLAKE2B_BLOCKBYTES; ++i) _buffer[i] = 0x00;
            for (i = 0; i < 8; ++i) _state[i] = 0UL;
            for (i = 0; i < 16; ++i) _m[i] = 0UL;
        }

        protected bool IsLastNode => _f1 == ulong.MaxValue;

        protected void SetLastNode() => _f1 = ulong.MaxValue;

        protected void ClearLastNode() => _f1 = 0;

        protected bool IsLastBlock => _f0 == ulong.MaxValue;

        protected void SetLastBlock()
        {
            if (IsLastNode) SetLastNode();
            _f0 = ulong.MaxValue;
        }

        protected void ClearLastBlock()
        {
            if (IsLastNode) ClearLastNode();
            _f0 = 0;
        }

        protected void IncrementCounter(ulong inc)
        {
            _counter0 += inc;
            if (_counter0 == 0) ++_counter1;
        }

        protected override void HashCore(byte[] array, int offset, int length) => Core(array, offset, length);

        public virtual void Core(byte[] array, int offset, int length)
        {
            if (array == null)
                throw new ArgumentNullException(nameof(array));

            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            if (offset + length > array.Length)
                throw new ArgumentOutOfRangeException("offset + length");

            if (!_isInitialized) Initialize();

            int bytesToFill;
            while (0 < length)
            {
                bytesToFill = Math.Min(length, BLAKE2B_BLOCKBYTES - _bufferFilled);
                Buffer.BlockCopy(array, offset, _buffer, _bufferFilled, bytesToFill);

                _bufferFilled += bytesToFill;
                offset += bytesToFill;
                length -= bytesToFill;

                if (_bufferFilled == BLAKE2B_BLOCKBYTES)
                {
                    IncrementCounter((ulong)BLAKE2B_BLOCKBYTES);

                    if (BitConverter.IsLittleEndian)
                        Buffer.BlockCopy(_buffer, 0, _m, 0, BLAKE2B_BLOCKBYTES);
                    else
                        for (var i = 0; i < BLAKE2B_BLOCKUINT64S; ++i)
                            _m[i] = BytesToUInt64(_buffer, (i << 3));

                    Compress();

                    _bufferFilled = 0;
                }
            }
        }

        partial void Compress();

        protected override byte[] HashFinal() => Final();

        public virtual byte[] Final()
        {
            var hash = new byte[HashSizeInBytes];
            Final(hash);
            return hash;
        }

        /* public virtual byte[] Final(bool isEndOfLayer)
		{
			var hash = new byte[HashSizeInBytes];
			Final(hash, isEndOfLayer);
			return hash;
		}
		public virtual void Final(byte[] hash)
		{
			Final(hash, false);
		} /**/

        public virtual void Final(byte[] hash) //, bool isEndOfLayer)
        {
            if (hash.Length != HashSizeInBytes)
                throw new ArgumentOutOfRangeException(nameof(hash), string.Format("hash.Length must be {0} HashSizeInBytes", HashSizeInBytes));

            if (!_isInitialized) Initialize();

            // Last compression
            IncrementCounter((ulong)_bufferFilled);

            SetLastBlock();

            for (var i = _bufferFilled; i < BLAKE2B_BLOCKBYTES; ++i)
                _buffer[i] = 0x00;

            if (BitConverter.IsLittleEndian)
                Buffer.BlockCopy(_buffer, 0, _m, 0, BLAKE2B_BLOCKBYTES);
            else
                for (var i = 0; i < BLAKE2B_BLOCKUINT64S; ++i)
                    _m[i] = BytesToUInt64(_buffer, (i << 3));

            Compress();

            // Output
            if (BitConverter.IsLittleEndian)
                Buffer.BlockCopy(_state, 0, hash, 0, HashSizeInBytes);
            else
                for (var i = 0; i < HashSizeInUInt64; ++i)
                    UInt64ToBytes(_state[i], hash, i << 3);

            _isInitialized = false;
        }

        public virtual void Compute(byte[] value, byte[] sourceCode)
        {
            Core(sourceCode, 0, sourceCode.Length);
            Final(value);
        }

        public virtual byte[] Compute(byte[] sourceCode)
        {
            Core(sourceCode, 0, sourceCode.Length);
            return Final();
        }

        public override byte[] Hash
        {
            get
            {
                // if (m_bDisposed) throw new ObjectDisposedException(null);
                // if (State != 0) throw new CryptographicUnexpectedOperationException(Environment.GetResourceString("Cryptography_HashNotYetFinalized"));

                // Output
                var hash = new byte[HashSizeInBytes];
                if (BitConverter.IsLittleEndian)
                    Buffer.BlockCopy(_state, 0, hash, 0, HashSizeInBytes);
                else
                    for (var i = 0; i < HashSizeInUInt64; ++i)
                        UInt64ToBytes(_state[i], hash, i << 3);
                return hash;
            }
        }

        private uint _fanOut;
        public uint FanOut
        {
            get => _fanOut;
            set
            {
                _fanOut = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private uint _maxHeight;
        public uint MaxHeight
        {
            get => _maxHeight;
            set
            {
                _maxHeight = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private ulong _leafSize;
        public ulong LeafSize
        {
            get => _leafSize;
            set
            {
                _leafSize = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private uint _intermediateHashSize;
        public uint IntermediateHashSize
        {
            get => _intermediateHashSize;
            set
            {
                _intermediateHashSize = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private byte[] _personalization;
        public byte[] Personalization
        {
            get => _personalization;
            set
            {
                _personalization = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private byte[] _salt;
        public byte[] Salt
        {
            get => _salt;
            set
            {
                _salt = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }

        private byte[] _key;
        public byte[] Key
        {
            get => _key;
            set
            {
                _key = value;
                _rawConfig = null;
                _isInitialized = false;
            }
        }
    }
}
