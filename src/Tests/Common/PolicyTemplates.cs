// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    /// <summary>
    /// Reusable policy definition fragments for tests.
    /// </summary>
    public static class PolicyTemplates
    {
        /// <summary>
        /// A minimal policy whose rule references a single field.
        /// </summary>
        /// <param name="field">The field name (an alias, a non-alias field, or a field reference expression).</param>
        public static string SingleFieldPolicy(string field) => @"
            {
              ""properties"": {
                ""mode"": ""Indexed"",
                ""policyRule"": {
                  ""if"": {
                    ""field"": """ + field + @""",
                    ""equals"": ""Allow""
                  },
                  ""then"": {
                    ""effect"": ""deny""
                  }
                }
              }
            }";
    }
}
