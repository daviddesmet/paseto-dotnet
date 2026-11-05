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

    [Theory]
    [InlineData(5L, 5, 0)]
    [InlineData(5, 7L, -1)]
    [InlineData((byte)9, 3L, 1)]
    [InlineData((short)-1, 0u, -1)]
    [InlineData(ulong.MaxValue, long.MaxValue, 1)]
    public void MixedIntegralTypesCompareExactly(object value, object valueToCompare, int expectedSign)
    {
        Comparer.TryCompare((IComparable)value, (IComparable)valueToCompare, out var result).ShouldBeTrue();
        Math.Sign(result).ShouldBe(expectedSign);
    }

    [Fact]
    public void MixedIntegralTypesAreEqualWhenValuesMatch()
    {
        Comparer.GetEqualsResult(5L, 5).ShouldBeTrue();
        Comparer.GetEqualsResult(5L, 6).ShouldBeFalse();
    }

    [Theory]
    [InlineData("5", 5)]
    [InlineData(5L, "5")]
    [InlineData(true, 1)]
    public void NonNumericMixedTypesAreNotComparable(object value, object valueToCompare)
    {
        // No implicit conversion between strings/booleans and integral numbers.
        Comparer.TryCompare((IComparable)value, (IComparable)valueToCompare, out var result).ShouldBeFalse();
        result.ShouldBe(0);
        Comparer.GetEqualsResult((IComparable)value, (IComparable)valueToCompare).ShouldBeFalse();
    }

    [Fact]
    public void GetComparisonResultReturnsComparison()
    {
        Comparer.GetComparisonResult(1, 2).ShouldBeLessThan(0);
        Comparer.GetEqualsResult(2, 2.0).ShouldBeTrue();
    }
}
