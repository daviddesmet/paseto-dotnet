namespace Paseto.Extensions;

using System;
using System.ComponentModel;
using System.Reflection;

using Paseto.Builder;

internal static class EnumExtensions
{
    /// <summary>
    /// Gets the string representation of a well-known claim name enum
    /// </summary>
    internal static string GetRegisteredClaimName(this RegisteredClaims value) => GetDescription(value);

    /// <summary>
    /// Gets the enum from a Description Attribute.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="description">The Description.</param>
    /// <returns>T.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="ArgumentException">Not found!;description</exception>
    internal static T FromDescription<T>(this string description)
    {
        var type = typeof(T);

        if (!type.IsEnum)
            throw new InvalidOperationException();

        foreach (var field in type.GetFields())
        {
            if (Attribute.GetCustomAttribute(field, typeof(DescriptionAttribute)) is DescriptionAttribute attribute)
            {
                if (attribute.Description == description)
                    return (T)field.GetValue(null);
            }
            else
            {
                if (field.Name == description)
                    return (T)field.GetValue(null);
            }
        }

        throw new ArgumentException("Not found!", nameof(description)); // or return default(T);
    }

    /// <summary>
    /// Gets the value of the Description Attribute from the enum.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="source">La fuente.</param>
    /// <returns>System.String.</returns>
    internal static string ToDescription<T>(this T source) where T : struct => GetDescription(source);

    /// <summary>
    /// Gets the value of the Describtion Attribute from the object.
    /// </summary>
    /// <param name="value">An object that is decorated with <see cref="DescriptionAttribute"/></param>
    private static string GetDescription(object value) => value.GetType().GetField(value.ToString()).GetCustomAttribute<DescriptionAttribute>()?.Description ?? value.ToString();
}
