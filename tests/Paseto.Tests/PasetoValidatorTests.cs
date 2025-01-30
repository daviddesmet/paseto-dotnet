namespace Paseto.Tests;

using System;
using Shouldly;
using Xunit;
using Builder;
using Paseto.Extensions;

public class PasetoValidatorTests
{
    private const string HelloPaseto = "Hello Paseto!";
    private const string IssuedBy = "Paragon Initiative Enterprises";

    [Theory]
    [MemberData(nameof(FutureTimes))]
    public void PayloadIssuedAtNextDayValidationFails(IComparable when, IComparable compareTo)
    {
        var iat = new Validators.IssuedAtValidator(CreateDateValidatorPayload(RegisteredClaims.IssuedAt, when));

        Action act = () => iat.Validate(compareTo);
        act.ShouldThrow<PasetoTokenValidationException>("Token is not yet valid");
    }

    [Theory]
    [MemberData(nameof(PastTimes))]
    public void PayloadIssuedAtPreviousDayValidationSucceeds(IComparable when, IComparable compareTo)
    {
        var iat = new Validators.IssuedAtValidator(CreateDateValidatorPayload(RegisteredClaims.IssuedAt, when));

        Action act = () => iat.Validate(compareTo);
        act.ShouldNotThrow();
    }

    [Theory]
    [MemberData(nameof(NowTimes))]
    public void PayloadIssuedAtSameDayValidationSucceeds(IComparable when)
    {
        var iat = new Validators.IssuedAtValidator(CreateDateValidatorPayload(RegisteredClaims.IssuedAt, when));

        Action act = () => iat.Validate(when);
        act.ShouldNotThrow();
    }

    [Theory]
    [MemberData(nameof(FutureTimes))]
    public void PayloadNotBeforeNextDayValidationFails(IComparable when, IComparable compareTo)
    {
        var nbf = new Validators.NotBeforeValidator(CreateDateValidatorPayload(RegisteredClaims.NotBefore, when));

        Action act = () => nbf.Validate(compareTo);
        act.ShouldThrow<PasetoTokenValidationException>("Token is not yet valid");
    }

    [Theory]
    [MemberData(nameof(PastTimes))]
    public void PayloadNotBeforeDayValidationSucceeds(IComparable when, IComparable compareTo)
    {
        var nbf = new Validators.NotBeforeValidator(CreateDateValidatorPayload(RegisteredClaims.NotBefore, when));

        Action act = () => nbf.Validate(compareTo);
        act.ShouldNotThrow();
    }

    [Theory]
    [MemberData(nameof(PastTimes))]
    public void PayloadExpirationTimeYesterdayValidationFails(IComparable when, IComparable compareTo)
    {
        var exp = new Validators.ExpirationTimeValidator(CreateDateValidatorPayload(RegisteredClaims.ExpirationTime, when));
        Action act = () => exp.Validate(compareTo);
        act.ShouldThrow<PasetoTokenValidationException>("Token has expired");
    }

    [Theory]
    [MemberData(nameof(FutureTimes))]
    public void PayloadExpirationNextDayTimeValidationSucceeds(IComparable when, IComparable compareTo)
    {
        var exp = new Validators.ExpirationTimeValidator(CreateDateValidatorPayload(RegisteredClaims.ExpirationTime, when));

        Action act = () => exp.Validate(compareTo);
        act.ShouldNotThrow();
    }

    [Fact]
    public void PayloadEqualValidationNonEqualFails()
    {
        var val = new Validators.EqualValidator(new PasetoPayload
        {
            { RegisteredClaims.Issuer.GetRegisteredClaimName(), IssuedBy }
        }, RegisteredClaims.Issuer.GetRegisteredClaimName());

        Action act = () => val.Validate(IssuedBy + ".");
        act.ShouldThrow<PasetoTokenValidationException>();
    }

    [Fact]
    public void PayloadEqualValidationTest()
    {
        var val = new Validators.EqualValidator(new PasetoPayload
        {
            { RegisteredClaims.Issuer.GetRegisteredClaimName(), IssuedBy }
        }, RegisteredClaims.Issuer.GetRegisteredClaimName());

        Action act = () => val.Validate(IssuedBy);
        act.ShouldNotThrow();
    }

    [Fact]
    public void PayloadCustomValidationNonEqualFails()
    {
        var val = new Validators.EqualValidator(new PasetoPayload
        {
            { "example", HelloPaseto }
        }, "example");

        Action act = () => val.Validate(HelloPaseto + "!");
        act.ShouldThrow<PasetoTokenValidationException>();
    }

    [Fact]
    public void PayloadCustomValidationTest()
    {
        var val = new Validators.EqualValidator(new PasetoPayload
        {
            { "example", HelloPaseto }
        }, "example");

        Action act = () => val.Validate(HelloPaseto);
        act.ShouldNotThrow();
    }

    public static TheoryData<IComparable, IComparable> FutureTimes => new()
    {
        { DateTime.UtcNow.AddHours(24), DateTime.UtcNow },
        { DateTimeOffset.UtcNow.AddHours(24), DateTimeOffset.UtcNow }
    };

    public static TheoryData<IComparable, IComparable> PastTimes => new()
    {
        { DateTime.UtcNow.AddHours(-24), DateTime.UtcNow },
        { DateTimeOffset.UtcNow.AddHours(-24), DateTimeOffset.UtcNow }
    };

    public static TheoryData<IComparable> NowTimes = new()
    {
        { DateTime.UtcNow },
        { DateTimeOffset.UtcNow }
    };

    private static PasetoPayload CreateDateValidatorPayload(RegisteredClaims claim, IComparable when) => new()
    {
        { claim.ToDescription(), when }
    };
}