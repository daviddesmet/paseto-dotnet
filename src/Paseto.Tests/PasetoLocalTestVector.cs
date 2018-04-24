namespace Paseto.Tests
{
    using Cryptography;

    public class PasetoLocalTestVector
    {
        public byte[] PrivateKey { get; private set; }
        public byte[] Nonce { get; private set; }
        public string Message { get; private set; }
        public string Footer { get; private set; }
        public string Token { get; private set; }

        public PasetoLocalTestVector(string key, string nonce, string msg, string footer, string token)
        {
            PrivateKey = CryptoBytes.FromHexString(key);
            Nonce = CryptoBytes.FromHexString(nonce);
            Message = msg;
            Footer = footer;
            Token = token;
        }

        public static PasetoLocalTestVector[] PasetoLocalTestVectors =
        {
            // Test Vector 2-E-1
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "000000000000000000000000000000000000000000000000",
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "",
                "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ"
            ),
            // Test Vector 2-E-2
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "000000000000000000000000000000000000000000000000",
                "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "",
                "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w"
            ),
            // Test Vector 2-E-3
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "",
                "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA"
            ),
            // Test Vector 2-E-4
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
                "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "",
                "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ"
            ),
            // Test Vector 2-E-5
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
                "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
                "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"
            ),
            // Test Vector 2-E-6
            new PasetoLocalTestVector(
                "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
                "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b",
                "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
                "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
                "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"
            )
        };
    }
}
