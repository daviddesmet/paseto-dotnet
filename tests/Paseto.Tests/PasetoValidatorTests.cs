namespace Paseto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    using FluentAssertions;
    using NaCl.Core.Internal;
    using Xunit;

    using Paseto.Builder;
    using Paseto.Cryptography;
    using Paseto.Cryptography.Key;
    using Paseto.Extensions;
    using Paseto.Protocol;
    using Paseto.Utils;
    using static Paseto.Utils.EncodingHelper;

    public class PasetoValidatorTests
    {
        private const string HelloPaseto = "Hello Paseto!";
        private const string IssuedBy = "Paragon Initiative Enterprises";
        private const string PublicKeyV1 = "<RSAKeyValue><Modulus>2Q3n8GRPEbcxAtT+uwsBnY08hhJF+Fby0MM1v5JbwlnQer7HmjKsaS97tbfnl87BwF15eKkxqHI12ntCSezxozhaUrgXCGVAXnUmZoioXTdtJgapFzBob88tLKhpWuoHdweRu9yGcWW3pD771zdFrRwa3h5alC1MAqAMHNid2D56TTsRj4CAfLSZpSsfmswfmHhDGqX7ZN6g/TND6kXjq4fPceFsb6yaKxy0JmtMomVqVTW3ggbVJhqJFOabwZ83/DjwqWEAJvfldz5g9LjvuislO5mJ9QEHBu7lnogKuX5g9PRTqP3c6Kus0/ldZ8CZvwWpxnxnwMRH10/UZ8TepQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string TokenV1 = "v1.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjE1MjEzMDc1MzMifTzjEcgP2a3p_IrMPuU9bH8OvOmV5Olr8DFK3rFu_7SngF_pZ0cU1X9w590YQeZTy37B1bPouoXZDQ9JDYBfalxG0cNn2aP4iKHgYuyrOqHaUTmbNeooKOvDPwwl6CFO3spTTANLK04qgPJnixeb9mvjby2oM7Qpmn28HAwwr_lSoOMPhiUSCKN4u-SA6G6OddQTuXY-PCV1VtgQA83f0J6Yy3x7MGH9vvqonQSuOG6EGLHJ09p5wXllHQyGZcRm_654aKpwh8CXe3w8ol3OfozGCMFF_TLo_EeX0iKSkE8AQxkrQ-Fe-3lP_t7xPkeNhJPnhAa0-DGLSFQIILsL31M";
        private const string PublicKeyV2 = "rJRRV5JmY3BRUmyWu2CRa1EnUSSNbOgrAMTIsgbX3Z4=";
        private const string TokenV2 = "v2.public.eyJleGFtcGxlIjoiSGVsbG8gUGFzZXRvISIsImV4cCI6IjIwMTgtMDQtMDdUMDU6MDQ6MDcuOTE5NjM3NVoifTuR3EYYCG12DjhIqPKiVmTkKx2ewCDrYNZHcoewiF-lpFeaFqKW3LkEgnW28UZxrBWA5wrLFCR5FP1qUlMeqQA";
        private const string LocalKeyV2 = "37ZJdkLlZ43aF8UO7GWqi7GrdO0zDZSpSFLNTAdmKdk=";
        private const string LocalTokenV2 = "v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248m9GasN_K5Yw2-CJksfXlbnEsTQHSMi49pqRzpvDTfo705J1ol98tc2e2Up62_4stDlPZQLAAwDeAQK0tS14h8JSYYunq3kvkeVTq6aNyCdw";
        private const string LocalTokenWithFooterV2 = "v2.local.ENG98mfmCWo7p8qEha5nuyv4lP5y8248m9GasN_K5Yw2-CJksfXlbnEsTQHSMi49pqRzpvDTfo705J1ol98tc2e2Up62_4stDlPZQLAAwDeAQK0tS14h8PyCfJzDW_mg6Bky_oW2HZw.eyJraWQiOiJnYW5kYWxmMCJ9";
        private const string ExpectedPublicPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T05:04:07.9196375Z\"}";
        private const string ExpectedLocalPayload = "{\"example\":\"Hello Paseto!\",\"exp\":\"2018-04-07T04:57:18.5865183Z\"}";
        private const string ExpectedFooter = "{\"kid\":\"gandalf0\"}";

        [Fact]
        public void PayloadNotBeforeNextDayValidationFails()
        {
            var nbf = new Validators.NotBeforeValidator(new PasetoPayload
            {
                { RegisteredClaims.NotBefore.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(24) }
            });

            Action act = () => nbf.Validate(DateTime.UtcNow);
            act.Should().Throw<TokenValidationException>().WithMessage("Token is not yet valid.");
        }

        [Fact]
        public void PayloadNotBeforeValidationTest()
        {
            var nbf = new Validators.NotBeforeValidator(new PasetoPayload
            {
                { RegisteredClaims.NotBefore.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(-24) }
            });

            Action act = () => nbf.Validate(DateTime.UtcNow);
            act.Should().NotThrow();
        }

        [Fact]
        public void PayloadExpirationTimeYesterdayValidationFails()
        {
            var exp = new Validators.ExpirationTimeValidator(new PasetoPayload
            {
                { RegisteredClaims.ExpirationTime.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(-24) }
            });

            Action act = () => exp.Validate(DateTime.UtcNow);
            act.Should().Throw<TokenValidationException>().WithMessage("Token has expired.");
        }

        [Fact]
        public void PayloadExpirationTimeValidationTest()
        {
            var exp = new Validators.ExpirationTimeValidator(new PasetoPayload
            {
                { RegisteredClaims.ExpirationTime.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(24) }
            });

            Action act = () => exp.Validate(DateTime.UtcNow);
            act.Should().NotThrow();
        }

        [Fact]
        public void PayloadEqualValidationNonEqualFails()
        {
            var val = new Validators.EqualValidator(new PasetoPayload
            {
                { RegisteredClaims.Issuer.GetRegisteredClaimName(), IssuedBy }
            }, RegisteredClaims.Issuer.GetRegisteredClaimName());

            Action act = () => val.Validate(IssuedBy + ".");
            act.Should().Throw<TokenValidationException>();
        }

        [Fact]
        public void PayloadEqualValidationTest()
        {
            var val = new Validators.EqualValidator(new PasetoPayload
            {
                { RegisteredClaims.Issuer.GetRegisteredClaimName(), IssuedBy }
            }, RegisteredClaims.Issuer.GetRegisteredClaimName());

            Action act = () => val.Validate(IssuedBy);
            act.Should().NotThrow();
        }

        [Fact]
        public void PayloadCustomValidationNonEqualFails()
        {
            var val = new Validators.EqualValidator(new PasetoPayload
            {
                { "example", HelloPaseto }
            }, "example");

            Action act = () => val.Validate(HelloPaseto + "!");
            act.Should().Throw<TokenValidationException>();
        }

        [Fact]
        public void PayloadCustomValidationTest()
        {
            var val = new Validators.EqualValidator(new PasetoPayload
            {
                { "example", HelloPaseto }
            }, "example");

            Action act = () => val.Validate(HelloPaseto);
            act.Should().NotThrow();
        }
    }
}
