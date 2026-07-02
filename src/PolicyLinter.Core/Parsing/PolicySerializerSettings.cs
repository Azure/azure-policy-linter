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
    }
}
