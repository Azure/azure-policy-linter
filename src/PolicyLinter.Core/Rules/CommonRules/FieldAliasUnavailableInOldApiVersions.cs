// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;

    /// <summary>
    /// Detects field aliases that map to properties missing in one or more old API versions of the resource type.
    /// </summary>
    public sealed class FieldAliasUnavailableInOldApiVersions : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Alias Unavailable In Old API Versions";
        private const string RuleDescription = "The field alias: '{0}' maps to property path that doesn't exist in one or more old API versions of resource type: '{1}'. API versions: '{2}'";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasUnavailableInOldApiVersions"/> class.
        /// </summary>
        public FieldAliasUnavailableInOldApiVersions() : base(
            identifier: "field-alias-unavailable-in-old-api-versions",
            category: Category.ResourceFields,
            title: RuleTitle,
            descriptionFormat: RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            // If this is a resolved alias reference.
            // - "Resolved" means that the field name expressed in the policy definition is a literal value and not a field\parameter reference itself.
            // - IsResolvedFieldReference() Is helpful here because an instance of the Reference class can express a field reference in multiple ways:
            //   - As a field reference (e.g. "[field('name')]" or a field leaf expression)
            //   - In a 'current()' function under a field count expression.
            if (expression.IsResolvedFieldReference() && FieldPathHelper.IsFieldAlias(expression.Identifier))
            {
                // If we have any metadata for it, it means that we successfully mapped the alias
                if (expression.ResourcePropertyMetadata.Any())
                {
                    var latestApiVersion = expression.ResourcePropertyMetadata
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Max(comparer: SuffixAwareApiVersionComparer.Instance);

                    var apiVersionsWithoutProperty = expression.ResourcePropertyMetadata
                        .Where(metadata => !metadata.Exists)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Distinct()
                        .OrderBy(v => v, comparer: SuffixAwareApiVersionComparer.Instance)
                        .ToArray();

                    if (apiVersionsWithoutProperty.Length != 0 && SuffixAwareApiVersionComparer.Instance.Compare(latestApiVersion, apiVersionsWithoutProperty.First()) > 0)
                    {
                        var resourceType = expression.ResourcePropertyMetadata.First().ResourceType;
                        var apiVersionsFormatted = string.Join(", ", apiVersionsWithoutProperty);
                        return new[] { this.CreateWarning(expression, expression.Identifier, resourceType, apiVersionsFormatted) };
                    }
                }
            }

            return Array.Empty<LinterOutput>();

        }
    }
}
