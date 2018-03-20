namespace Paseto.Utils
{
    using System;
    using System.Globalization;

    /// <summary>
    /// Unix Time.
    /// </summary>
    public static class UnixEpoch
    {
        /// <summary>
        /// Describes a point in time, defined as the number of seconds that have elapsed since 00:00:00 UTC, Thursday, 1 January 1970, not counting leap seconds.
        /// See https://en.wikipedia.org/wiki/Unix_time />
        /// </summary>
        public static DateTime Epoch { get; } = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Converts from Unix Time.
        /// </summary>
        /// <param name="unixTime">The Unix Time.</param>
        /// <returns>DateTime.</returns>
        public static DateTime FromUnixTime(long unixTime) => Epoch.AddSeconds(unixTime);

        /// <summary>
        /// Converts to Unix Time.
        /// </summary>
        /// <param name="time">The Utc DateTime.</param>
        /// <returns>System.Int64.</returns>
        public static long ToUnixTime(DateTimeOffset time) => Convert.ToInt64(Math.Round((time - Epoch).TotalSeconds));

        /// <summary>
        /// Converts to Unix Time as string.
        /// </summary>
        /// <param name="time">The Utc DateTime.</param>
        /// <returns>System.String.</returns>
        public static string ToUnixTimeString(DateTimeOffset time) => ToUnixTime(time).ToString(CultureInfo.InvariantCulture);
    }
}
