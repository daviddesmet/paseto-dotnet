#if NETFRAMEWORK
namespace System.Runtime.CompilerServices;

/// <summary>
/// Polyfill supplying the <c>GetSubArray</c> helper the C# compiler emits when an array is sliced
/// with a range (e.g. <c>array[a..b]</c>). .NET Framework's <see cref="RuntimeHelpers"/> does not
/// include this method, so range-based array slicing does not compile without it.
/// </summary>
/// <remarks>
/// This type intentionally shadows the BCL <c>RuntimeHelpers</c> for this assembly's compilation
/// (compiler warning CS0436); it is only referenced by the compiler for array range slicing, which
/// the BCL type cannot satisfy on this framework.
/// </remarks>
internal static class RuntimeHelpers
{
    public static T[] GetSubArray<T>(T[] array, Range range)
    {
        var (offset, length) = range.GetOffsetAndLength(array.Length);

        if (length == 0)
            return Array.Empty<T>();

        var dest = new T[length];
        Array.Copy(array, offset, dest, 0, length);
        return dest;
    }
}
#endif
