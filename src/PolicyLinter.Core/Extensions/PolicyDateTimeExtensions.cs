// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Extensions
{
    using System;
    using System.Globalization;

    /// <summary>
    /// The Policy DateTime extensions.
    /// </summary>
    public static class PolicyDateTimeExtensions
    {
        /// <summary>
        /// The supported date-time format strings
        /// </summary>
        private static readonly string[] supportedISO8601Formats = new string[] { "o", "yyyy-MM-ddTHH:mm:ss.FFFFFFFZ" };

        /// <summary>
        /// Parses the given string value if it is in the Universal ISO 8601 DateTime format <c>yyyy-MM-ddTHH:mm:ss.FFFFFFFZ</c>
        /// </summary>
        /// <param name="stringValue">The string value to parse.</param>
        /// <param name="universalISODateTime">The resulting date time if parsing is successful.</param>
        public static bool TryParseISO8601UniversalDateTime(this string stringValue, out DateTime universalISODateTime)
        {
            return DateTime.TryParseExact(
                    s: stringValue,
                    formats: supportedISO8601Formats,
                    provider: null,
                    style: DateTimeStyles.AdjustToUniversal,
                    result: out universalISODateTime) &&
                universalISODateTime.Kind == DateTimeKind.Utc;
        }

        /// <summary>
        /// Converts DateTime to Round-trip format string <c>yyyy-MM-ddTHH:mm:ss.fffffffZ</c> which is ISO 8601 compliant
        /// </summary>
        /// <param name="datetime">The DateTime.</param>
        public static string ToRoundtripFormatString(this DateTime datetime)
        {
            return datetime.ToUniversalTime().ToString("o");
        }
    }
}
