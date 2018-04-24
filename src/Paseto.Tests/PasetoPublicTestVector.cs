namespace Paseto.Tests
{
    using Cryptography;

    public class PasetoPublicTestVector
    {
        public byte[] PrivateKey { get; private set; }
        public string Message { get; private set; }
        public string Footer { get; private set; }
        public string Token { get; private set; }

        public PasetoPublicTestVector(string key, string msg, string footer, string token)
        {
            PrivateKey = CryptoBytes.FromHexString(key);
            Message = msg;
            Footer = footer;
            Token = token;
        }

        public static PasetoPublicTestVector[] PasetoPublicTestVectors =
        {
            // Test Vector 2-S-1
            new PasetoPublicTestVector(
                "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"
                    + "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "",
                "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw"
            ),
            // Test Vector 2-S-2
            new PasetoPublicTestVector(
                "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"
                    + "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
                "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"
            )
        };
    }
}
