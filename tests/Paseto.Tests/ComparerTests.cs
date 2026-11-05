namespace Paseto.Tests;

using System;

using Shouldly;
using Xunit;

using Paseto.Validators.Internal;

[Trait("Category", "CI")]
public class ComparerTests
{
    [Fact]
    public void SameTypeUsesDefaultComparison()
    {
        Comparer.TryCompare(5, 3, out var result).ShouldBeTrue();
        result.ShouldBeGreaterThan(0);
    }

    [Theory]
    [InlineData(5, 5.0, 0)]
    [InlineData(2.5, 3, -1)]
    [InlineData(4f, 3, 1)]
    public void MixedTypesWithFractionalValueCompareAsDouble(object value, object valueToCompare, int expectedSign)
    {
        Comparer.TryCompare((IComparable)value, (IComparable)valueToCompare, out var result).ShouldBeTrue();
        Math.Sign(result).ShouldBe(expectedSign);
    }

    [Fact]
    public void MixedTypesWithDecimalCompareAsDouble()
    {
        Comparer.TryCompare(2.5m, 3, out var result).ShouldBeTrue();
        result.ShouldBeLessThan(0);
    }

    [Fact]
    public void MixedIntegralTypesFallBackToEquals()
    {
        // The long fallback unboxes both values, so mixed integral types (long vs int) cannot be
        // compared and TryCompare reports failure; GetEqualsResult then falls back to Equals.
        Comparer.TryCompare(5L, 5, out var result).ShouldBeFalse();
        result.ShouldBe(0);
        Comparer.GetEqualsResult(5L, 5).ShouldBeFalse();
    }

    [Fact]
    public void GetComparisonResultReturnsComparison()
    {
        Comparer.GetComparisonResult(1, 2).ShouldBeLessThan(0);
        Comparer.GetEqualsResult(2, 2.0).ShouldBeTrue();
    }
}
