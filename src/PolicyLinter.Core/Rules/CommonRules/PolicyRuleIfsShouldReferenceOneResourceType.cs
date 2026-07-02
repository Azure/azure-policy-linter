// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects policies whose if condition references multiple resource types.
    /// </summary>
    public sealed class PolicyRuleIfsShouldReferenceOneResourceType : LinterRule<IfCondition>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PolicyRuleIfsShouldReferenceOneResourceType"/> class.
        /// </summary>
        public PolicyRuleIfsShouldReferenceOneResourceType() : base(
            identifier: "policy-rule-should-contain-one-resource-type",
            category: Category.BestPractices,
            title: "Policies should reference one resource type",
            descriptionFormat: "{0}",
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var referencedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var usedWildCardOperator = false;

            // Create a visitor to traverse the expression tree and check how many resource types
            var visitor = new PolicyExpressionVisitor
            {
                Visit = (expression) =>
                {
                    // Look for expressions of type reference
                    if (expression is Reference reference && reference.IsResolvedFieldReference())
                    {
                        referencedResourceTypes.UnionWith(
                            reference.ResourcePropertyMetadata
                            .Select(metadata => metadata.ResourceType));

                        return;
                    }

                    if (expression is LeafCondition leaf && leaf.Field?.FieldAccessorReference != null)
                    {
                        var fieldName = leaf.Field.FieldAccessorReference.Identifier;
                        if (!string.Equals(fieldName, "type", StringComparison.OrdinalIgnoreCase) ||
                            leaf.Operator == null)
                        {
                            return;
                        }

                        // Check for wildcard operators
                        if (CheckWildCardOperator(leaf.Operator) && !usedWildCardOperator)
                        {
                            usedWildCardOperator = true;
                        }

                        var resourceTypes = ExtractResourceTypes(leaf);
                        foreach (var resourceType in resourceTypes)
                        {
                            _ = referencedResourceTypes.Add(resourceType);
                        }
                    }
                }
            };

            // Visit all expressions in the policy definition
            expression.Visit(visitor);

            var warnings = new List<LinterOutput>();
            if (referencedResourceTypes.Count > 1)
            {
                warnings.Add(this.CreateWarning(expression, $"It is best practice for the policy rule to only reference one resource type, referenced resource types {string.Join(", ", referencedResourceTypes)}."));
            }

            if (usedWildCardOperator)
            {
                warnings.Add(this.CreateWarning(expression, "The policy uses wildcard operators when checking resource types, which may lead to unintended matches."));
            }

            return warnings.ToArray();
        }

        /// <summary>
        /// Check for wildcard operator and return a warning if found.
        /// </summary>
        /// <param name="leafOperator"></param>
        /// <returns></returns>
        private static bool CheckWildCardOperator(Property leafOperator)
        {
            return string.Equals(leafOperator.Name, "contains", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(leafOperator.Name, "like", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(leafOperator.Name, "match", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(leafOperator.Name, "matchInsensitively", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts resource types from an operator value (can be string or array).
        /// </summary>
        /// <param name="leaf">The operator (could be string or array)</param>
        /// <returns>A list of extracted resource types</returns>
        private static List<string> ExtractResourceTypes(LeafCondition leaf)
        {
            var resourceTypes = new List<string>();
            var leafOperator = leaf.Operator;
            if (leafOperator == null)
            {
                return resourceTypes;
            }

            var stringsToExtractFrom = new List<string>();
            // We need to handle "not" conditions, should check that the path has an even number or 0 "nots"
            var notCount = leaf.PathSegments.Aggregate(0, (acc, segment) =>
                segment.Contains("not", StringComparison.OrdinalIgnoreCase) ? acc + 1 : acc);
            // Handle array values (e.g., from "in" operator)
            // Make sure were in an even number of nots, we're inside a not condition
            if (notCount % 2 == 0 && string.Equals(leafOperator.Name, "in", StringComparison.OrdinalIgnoreCase))
            {
                var array = (JArray)leafOperator.Value;
                foreach (var item in array)
                {
                    var stringValue = item.ToString();
                    stringsToExtractFrom.Add(stringValue);
                }
            }
            else if (string.Equals(leafOperator.Name, "equals", StringComparison.OrdinalIgnoreCase))
            {
                stringsToExtractFrom.Add(leafOperator.Value.ToString());
            }

            foreach (var stringValue in stringsToExtractFrom)
            {
                var extractedType = ExtractResourceTypeFromString(stringValue);
                if (!string.IsNullOrEmpty(extractedType))
                {
                    resourceTypes.Add(extractedType);
                }
            }
            return resourceTypes;
        }

        /// <summary>
        /// Extracts a resource type from a string value.
        /// Resource types are in the format "Microsoft.Provider/resourceType".
        /// </summary>
        /// <param name="value">The string value to extract from</param>
        /// <returns>The extracted resource type, or null if not a valid resource type format</returns>
        private static string? ExtractResourceTypeFromString(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            // Split by '/' to check if this looks like a resource type
            var segments = value.Split('/');

            // Resource types are in the format "Microsoft.Provider/resourceType"
            // So we need at least 2 segments
            // And check if the first segment looks like a provider namespace (contains a dot)
            if (segments.Length >= 2 && segments[0].Contains('.', StringComparison.OrdinalIgnoreCase))
            {
                // Return the resource type (first two segments)
                return $"{segments[0]}/{segments[1]}";
            }

            return null;
        }
    }
}
