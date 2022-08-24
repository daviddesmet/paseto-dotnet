namespace Paseto.Tests.Extensions;

using System;
using FluentAssertions;
using Paseto.Extensions;
using Xunit;

public class SpanExtensionsTests
{
    [Theory]
    [InlineData(0, 0, 10)]
    [InlineData(0, 1, 5)]
    [InlineData(1, 0, 5)]
    [InlineData(5, 5, 5)]
    public void SpanCopyShouldCorrectlyCopySlice(int sourceIndex, int destinationIndex, int length)
    {
        // Arrange
        var source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        var expected = new byte[] { 31, 32, 33, 34, 35, 36, 37, 38, 39, 40 };
        var destination = new byte[] { 31, 32, 33, 34, 35, 36, 37, 38, 39, 40 };
        Array.Copy(source, sourceIndex, expected, destinationIndex, length);

        // Act
        SpanExtensions.Copy(source, sourceIndex, destination, destinationIndex, length);

        // Assert
        destination.Should().BeEquivalentTo(expected);
    }

    [Theory]
    [InlineData(0, 0, 11)]
    [InlineData(0, 0, -1)]
    [InlineData(-1, -1, 10)]
    [InlineData(-1, 0, 10)]
    [InlineData(0, -1, 10)]
    [InlineData(1, 1, 10)]
    [InlineData(1, 0, 10)]
    [InlineData(0, 1, 10)]
    [InlineData(11, 11, 10)]
    [InlineData(11, 0, 10)]
    [InlineData(0, 11, 10)]
    public void SpanCopyShouldThrowErrorWhenGivenOutOfBoundsArguments(int sourceIndex, int destinationIndex, int length)
    {
        // Arrange
        var source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var destination = new byte[] { 31, 32, 33, 34, 35, 36, 37, 38, 39, 40 };

        // Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => SpanExtensions.Copy(source, sourceIndex, destination, destinationIndex, length));
    }
}