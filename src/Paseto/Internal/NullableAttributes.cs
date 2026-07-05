#if NETFRAMEWORK
namespace System.Diagnostics.CodeAnalysis;

/// <summary>
/// Polyfill for the nullable-analysis attribute, which exists only as an internal type in the
/// .NET Framework BCL and is therefore inaccessible to consuming code.
/// </summary>
[AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property, Inherited = false)]
internal sealed class NotNullAttribute : Attribute
{
}
#endif
