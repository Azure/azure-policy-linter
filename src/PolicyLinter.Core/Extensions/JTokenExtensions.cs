// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Extensions
{
    using System;
    using System.Globalization;
    using System.Runtime.CompilerServices;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// <c>JSON</c> extensions.
    /// </summary>
    public static class JTokenExtensions
    {
        /// <summary>
        /// Gets value from JSON token with minimal overhead.
        /// </summary>
        /// <param name="token">The JSON token.</param>
        /// <param name="returnEmptyForNulls">Flag to dictate whether to return null or empty string for null jtokens</param>
        public static string? ToStringValue(this JToken token, bool returnEmptyForNulls = true)
        {
            if (token == null)
            {
                return returnEmptyForNulls ? string.Empty : null;
            }

            var value = ((JValue)token).Value;

            // Note: JToken.ToString() implementation returns "". We need to keep the same behavior. 
            if (returnEmptyForNulls && token.Type == JTokenType.Null && value == null)
            {
                return string.Empty;
            }

            return value is string variable ? variable : JTokenExtensions.ChangeType<string>(value);
        }

        /// <summary>
        /// Changes the type of the value.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="value">The token value.</param>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static T? ChangeType<T>(object? value)
        {
            var type = typeof(T);
            var underlyingType = Nullable.GetUnderlyingType(type);

            return value == null && (type.IsClass || underlyingType != null)
                ? default
                : (T?)Convert.ChangeType(value, underlyingType ?? type, CultureInfo.InvariantCulture);
        }
    }
}
