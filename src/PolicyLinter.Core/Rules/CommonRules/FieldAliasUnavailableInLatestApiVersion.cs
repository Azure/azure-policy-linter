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
    /// Detects field aliases referring to properties that do not exist in the latest API version of the resource type.
    /// </summary>
    public sealed class FieldAliasUnavailableInLatestApiVersion : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Alias Unavailable In Latest API Version";
        private const string RuleDescription = "The field alias: '{0}' is referring to a property that doesn't exist in the latest API version ({1}) of resource type: '{2}'. This most likely means that the referenced property is deprecated and the policy might not work as intended.";

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

                    if (latestApiVersionMetadata != null && !latestApiVersionMetadata.Exists)
                    {
                        var latestApiVersion = latestApiVersionMetadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance);
                        var resourceType = latestApiVersionMetadata.ResourceType;
                        return new[] { this.CreateError(expression, expression.Identifier, latestApiVersion ?? string.Empty, resourceType) };
                    }
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
