// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing
{
    using System.Collections.Generic;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Provides configuration settings for JSON serialization when writing linter output files.
    /// This is separate from PolicySerializerSettings to ensure output formatting doesn't affect
    /// the accuracy of line and position information when parsing input policy definitions.
    /// </summary>
    public class LinterOutputSerializerSettings
    {
        /// <summary>
        /// The JSON serializer settings used for writing formatted linter output files.
        /// Includes indented formatting for human readability.
        /// </summary>
        public static readonly JsonSerializerSettings Settings = new()
        {
            MaxDepth = JsonExtensions.JsonSerializationMaxDepth,
            TypeNameHandling = TypeNameHandling.None,
            Formatting = Formatting.Indented,

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
