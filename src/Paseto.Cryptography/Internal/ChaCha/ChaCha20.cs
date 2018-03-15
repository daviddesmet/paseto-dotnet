namespace Paseto.Cryptography.Internal.ChaCha
{
    using System;

    /// <remarks>
    /// https://tools.ietf.org/html/rfc7539
    /// </remarks>
    internal sealed class ChaCha20
    {
        private const int NUMBER_OF_STATES = 16;
        private const int MINIMUM_NUMBER_OF_USER_DEFINED_STATES = NUMBER_OF_STATES - 4;

        // constant states
        internal uint State0 = 0X61707865;
        internal uint State1 = 0X3320646E;
        internal uint State2 = 0X79622D32;
        internal uint State3 = 0X6B206574;

        // key states
        internal uint State4 = 0X03020100;
        internal uint State5 = 0X07060504;
        internal uint State6 = 0X0B0A0908;
        internal uint State7 = 0X0F0E0D0C;
        internal uint State8 = 0X13121110;
        internal uint State9 = 0X17161514;
        internal uint StateA = 0X1B1A1918;
        internal uint StateB = 0X1F1E1D1C;

        // counter state
        internal uint StateC = 0X00000001;

        // nonce states
        internal uint StateD = 0X09000000;
        internal uint StateE = 0X4A000000;
        internal uint StateF = 0X00000000;

        internal ChaCha20() { }

        internal ChaCha20(uint[] state)
        {
            if (state is null)
                throw new ArgumentNullException(nameof(state));

            if (state.Length != MINIMUM_NUMBER_OF_USER_DEFINED_STATES)
                throw new ArgumentException("Invalid number of user defined states!", nameof(state));

            State4 = state[0];
            State5 = state[1];
            State6 = state[2];
            State7 = state[3];
            State8 = state[4];
            State9 = state[5];
            StateA = state[6];
            StateB = state[7];
            StateC = state[8];
            StateD = state[9];
            StateE = state[10];
            StateF = state[11];
        }

        internal ChaCha20 Copy()
        {
            var temp = new ChaCha20()
            {
                State0 = State0,
                State1 = State1,
                State2 = State2,
                State3 = State3,
                State4 = State4,
                State5 = State5,
                State6 = State6,
                State7 = State7,
                State8 = State8,
                State9 = State9,
                StateA = StateA,
                StateB = StateB,
                StateC = StateC,
                StateD = StateD,
                StateE = StateE,
                StateF = StateF
            };

            return temp;
        }

        private static void Block(ChaCha20 chacha20)
        {
            var temp = chacha20.Copy();

            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);
            FullRound(temp);

            unchecked
            {
                chacha20.State0 += temp.State0;
                chacha20.State1 += temp.State1;
                chacha20.State2 += temp.State2;
                chacha20.State3 += temp.State3;
                chacha20.State4 += temp.State4;
                chacha20.State5 += temp.State5;
                chacha20.State6 += temp.State6;
                chacha20.State7 += temp.State7;
                chacha20.State8 += temp.State8;
                chacha20.State9 += temp.State9;
                chacha20.StateA += temp.StateA;
                chacha20.StateB += temp.StateB;
                chacha20.StateC += temp.StateC;
                chacha20.StateD += temp.StateD;
                chacha20.StateE += temp.StateE;
                chacha20.StateF += temp.StateF;
            }
        }

        private static void FullRound(ChaCha20 chacha20)
        {
            QuarterRound(ref chacha20.State0, ref chacha20.State4, ref chacha20.State8, ref chacha20.StateC);
            QuarterRound(ref chacha20.State1, ref chacha20.State5, ref chacha20.State9, ref chacha20.StateD);
            QuarterRound(ref chacha20.State2, ref chacha20.State6, ref chacha20.StateA, ref chacha20.StateE);
            QuarterRound(ref chacha20.State3, ref chacha20.State7, ref chacha20.StateB, ref chacha20.StateF);
            QuarterRound(ref chacha20.State0, ref chacha20.State5, ref chacha20.StateA, ref chacha20.StateF);
            QuarterRound(ref chacha20.State1, ref chacha20.State6, ref chacha20.StateB, ref chacha20.StateC);
            QuarterRound(ref chacha20.State2, ref chacha20.State7, ref chacha20.State8, ref chacha20.StateD);
            QuarterRound(ref chacha20.State3, ref chacha20.State4, ref chacha20.State9, ref chacha20.StateE);
        }

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            unchecked
            {
                d = RotateLeft(d ^= (a += b), 16);
                b = RotateLeft(b ^= (c += d), 12);
                d = RotateLeft(d ^= (a += b), 8);
                b = RotateLeft(b ^= (c += d), 7);
            }
        }
        
        private static uint RotateLeft(uint value, int count)
        {
            return ((value << count) | (value >> ((-count) & 31)));
        }
    }
}
