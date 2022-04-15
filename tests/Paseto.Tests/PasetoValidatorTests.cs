namespace Paseto.Tests
{
    using System;

    using FluentAssertions;
    using Xunit;

    using Paseto.Builder;
    using Paseto.Extensions;

    public class PasetoValidatorTests
    {
        private const string HelloPaseto = "Hello Paseto!";
        private const string IssuedBy = "Paragon Initiative Enterprises";

        [Fact]
        public void PayloadIssuedAtNextDayValidationFails()
        {
            var iat = new Validators.IssuedAtValidator(new PasetoPayload
            {
                { RegisteredClaims.IssuedAt.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(24) }
            });

            Action act = () => iat.Validate(DateTime.UtcNow);
            act.Should().Throw<PasetoTokenValidationException>().WithMessage("Token is not yet valid");
        }

        [Fact]
        public void PayloadIssuedAtPreviousDayValidationSucceeds()
        {
            var iat = new Validators.IssuedAtValidator(new PasetoPayload
            {
                { RegisteredClaims.IssuedAt.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(-24) }
            });

            Action act = () => iat.Validate(DateTime.UtcNow);
            act.Should().NotThrow();
        }

        [Fact]
        public void PayloadIssuedAtSameDayValidationSucceeds()
        {
            var now = DateTime.UtcNow;

            var iat = new Validators.IssuedAtValidator(new PasetoPayload
            {
                { RegisteredClaims.IssuedAt.GetRegisteredClaimName(), now }
            });

            Action act = () => iat.Validate(now);
            act.Should().NotThrow();
        }

        [Fact]
        public void PayloadNotBeforeNextDayValidationFails()
        {
            var nbf = new Validators.NotBeforeValidator(new PasetoPayload
            {
                { RegisteredClaims.NotBefore.GetRegisteredClaimName(), DateTime.UtcNow.AddHours(24) }
            });

            Action act = () => nbf.Validate(DateTime.UtcNow);
            act.Should().Throw<PasetoTokenValidationException>().WithMessage("Token is not yet valid");
        }

        [Fact]
        public void PayloadNotBeforeDayValidationSucceeds()
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
            act.Should().Throw<PasetoTokenValidationException>().WithMessage("Token has expired");
        }

        [Fact]
        public void PayloadExpirationNextDayTimeValidationSucceeds()
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
            act.Should().Throw<PasetoTokenValidationException>();
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
            act.Should().Throw<PasetoTokenValidationException>();
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
