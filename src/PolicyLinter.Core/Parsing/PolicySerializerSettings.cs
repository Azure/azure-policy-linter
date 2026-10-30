// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Parsing
{
    using System.Collections.Generic;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Provides configuration settings for JSON serialization and deserialization of policies.
    /// </summary>
    public class PolicySerializerSettings
    {
        /// <summary>
        /// The JSON serializer settings used for policy serialization and deserialization.
        /// </summary>
        public static readonly JsonSerializerSettings Settings = new()
        {
            MaxDepth = JsonExtensions.JsonSerializationMaxDepth,
            TypeNameHandling = TypeNameHandling.None,

            DateParseHandling = DateParseHandling.None,
            DateTimeZoneHandling = DateTimeZoneHandling.Utc,

            NullValueHandling = NullValueHandling.Ignore,
            MissingMemberHandling = MissingMemberHandling.Ignore,
            ContractResolver = new CamelCasePropertyNamesWithOverridesContractResolver(),

            Converters = new List<JsonConverter>
            {
                new GenericObjectPropertyConverter(),
                new StringEnumConverter(),
                new AdjustToUniversalIsoDateTimeConverter()
            }
        };

        /// <summary>
        /// A serializer using <see cref="Settings"/>. Use it to convert already-loaded tokens (e.g. effect details) to parsing objects.
        /// </summary>
        public static readonly JsonSerializer Serializer = JsonSerializer.Create(PolicySerializerSettings.Settings);
    }
}
