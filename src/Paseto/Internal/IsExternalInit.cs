#if NETFRAMEWORK
namespace System.Runtime.CompilerServices;

using System.ComponentModel;

/// <summary>
/// Polyfill that lets the C# compiler emit <c>init</c>-only property setters when targeting
/// .NET Framework, which does not ship the <see cref="IsExternalInit"/> type in its BCL.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
internal static class IsExternalInit
{
}
#endif
