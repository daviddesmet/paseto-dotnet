namespace Paseto.Extensions;

using System;

internal static class SpanExtensions
{
    public static void Copy(ReadOnlySpan<byte> sourceSpan, int sourceIndex, Span<byte> destinationSpan, int destinationIndex, int length) => sourceSpan.Slice(sourceIndex, length).CopyTo(destinationSpan.Slice(destinationIndex, length));
}