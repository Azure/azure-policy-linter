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
    /// Detects field aliases referring to properties that exist in one or more older API versions but do not exist in the latest API version of the resource type.
    /// </summary>
    public sealed class FieldAliasUnavailableInLatestApiVersion : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Alias Unavailable In Latest API Version";
        private const string RuleDescription = "The field alias: '{0}' is referring to a property that doesn't exist in the latest API version ({1}) of resource type: '{2}'. The policy might not work as intended.";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasUnavailableInLatestApiVersion"/> class.
        /// </summary>
        public FieldAliasUnavailableInLatestApiVersion() : base(
            identifier: "field-alias-unavailable-in-latest-api-version",
            category: Category.ResourceFields,
            title: RuleTitle,
            descriptionFormat: RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.IsResolvedFieldReference() && FieldPathHelper.IsFieldAlias(expression.Identifier))
            {
                if (expression.ResourcePropertyMetadata.Any())
                {
                    var latestApiVersionMetadata = expression.ResourcePropertyMetadata
                        .MaxBy(
                            keySelector: metadata => metadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance),
                            comparer: SuffixAwareApiVersionComparer.Instance);

                    // Only the "deprecated" state belongs to this rule: the property is missing in the latest API
                    // version but exists in at least one API version. The "missing in all versions" state is covered
                    // by a dedicated rule.
                    if (latestApiVersionMetadata != null
                        && !latestApiVersionMetadata.Exists
                        && expression.ResourcePropertyMetadata.Any(metadata => metadata.Exists))
                    {
                        // A metadata group always carries at least one API version, so Max is never null here.
                        var latestApiVersion = latestApiVersionMetadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance);
                        var resourceType = latestApiVersionMetadata.ResourceType;
                        return new[] { this.CreateError(expression, expression.Identifier, latestApiVersion!, resourceType) };
                    }
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
