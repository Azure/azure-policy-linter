// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects policies whose if condition references more than one resource type,
    /// combining the resource types named in 'type' field conditions with those
    /// resolved from field aliases.
    /// </summary>
    public sealed class PolicyRuleReferencesMultipleResourceTypes : LinterRule<IfCondition>
    {
        private const string RuleDescription =
            "The policy rule references multiple resource types: {0}. Targeting several related types is a valid pattern; if this is unintended, target a single type and group policies with an initiative.";

        /// <summary>
        /// Initializes a new instance of the <see cref="PolicyRuleReferencesMultipleResourceTypes"/> class.
        /// </summary>
        public PolicyRuleReferencesMultipleResourceTypes() : base(
            identifier: "policy-rule-references-multiple-resource-types",
            category: Category.BestPractices,
            title: "Policy Rule References Multiple Resource Types",
            descriptionFormat: PolicyRuleReferencesMultipleResourceTypes.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var referencedResourceTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var visitor = new PolicyExpressionVisitor
            {
                Visit = (expression) =>
                {
                    // Resource types resolved from field aliases (e.g. [field('...')]).
                    if (expression is Reference reference && reference.IsResolvedFieldReference())
                    {
                        referencedResourceTypes.UnionWith(
                            reference.ResourcePropertyMetadata
                            .Select(metadata => metadata.ResourceType));

                        return;
                    }

                    // Resource types named explicitly in a 'type' field condition.
                    if (expression is LeafCondition leaf && leaf.Field?.FieldAccessorReference != null)
                    {
                        var fieldName = leaf.Field.FieldAccessorReference.Identifier;
                        if (!string.Equals(fieldName, "type", StringComparison.OrdinalIgnoreCase) ||
                            leaf.Operator == null)
                        {
                            return;
                        }

                        foreach (var resourceType in ExtractResourceTypes(leaf, leaf.Operator))
                        {
                            _ = referencedResourceTypes.Add(resourceType);
                        }
                    }
                }
            };

            expression.Visit(visitor);

            if (referencedResourceTypes.Count <= 1)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression, string.Join(", ", referencedResourceTypes)),
            };
        }

        /// <summary>
        /// Extracts resource types from a non-negated 'type' leaf condition's operator value
        /// (a single string for 'equals' or an array for 'in').
        /// </summary>
        /// <param name="leaf">The 'type' field condition to inspect.</param>
        /// <param name="leafOperator">The condition's operator.</param>
        /// <returns>The resource types named by the condition.</returns>
        private static List<string> ExtractResourceTypes(LeafCondition leaf, Property leafOperator)
        {
            var resourceTypes = new List<string>();

            // A parameterized operand (e.g. "[parameters('types')]") is not a resource type literal,
            // so there is nothing to extract.
            if (!leafOperator.HasLiteralValue)
            {
                return resourceTypes;
            }

            var stringsToExtractFrom = new List<string>();

            var notCount = leaf.PathSegments.Aggregate(0, (acc, segment) =>
                string.Equals(segment, "not", StringComparison.OrdinalIgnoreCase) ? acc + 1 : acc);
            if (notCount % 2 != 0)
            {
                return resourceTypes;
            }

            if (string.Equals(leafOperator.Name, "in", StringComparison.OrdinalIgnoreCase))
            {
                var array = (JArray)leafOperator.Value;
                foreach (var item in array)
                {
                    stringsToExtractFrom.Add(item.ToString());
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
        /// Resource types are in the format "Microsoft.Provider/resourceType[/childType...]".
        /// </summary>
        /// <param name="value">The string value to extract from.</param>
        /// <returns>The extracted resource type, or null if not a valid resource type format.</returns>
        private static string? ExtractResourceTypeFromString(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            var segments = value.Split('/');

            if (segments.Length >= 2 && segments[0].Contains('.', StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }

            return null;
        }
    }
}
