namespace Paseto.Extensions
{
    using System.ComponentModel;
    using System.Reflection;

    using Paseto.Builder;

    internal static class EnumExtensions
    {
        /// <summary>
        /// Gets the string representation of a well-known claim name enum
        /// </summary>
        public static string GetRegisteredClaimName(this RegisteredClaims value) => GetDescription(value);

        /// <summary>
        /// Gets the value of the Description Attribute from the enum.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="source">La fuente.</param>
        /// <returns>System.String.</returns>
        public static string ToDescription<T>(this T source) where T : struct => GetDescription(source);

        /// <summary>
        /// Gets the value of the Describtion Attribute from the object.
        /// </summary>
        /// <param name="value">An object that is decorated with <see cref="DescriptionAttribute"/></param>
        private static string GetDescription(object value) => value.GetType().GetField(value.ToString()).GetCustomAttribute<DescriptionAttribute>()?.Description ?? value.ToString();
    }
}
