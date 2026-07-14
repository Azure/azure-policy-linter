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
    /// Detects field aliases that map to conditional resource properties which may not always exist.
    /// </summary>
    public sealed class ConditionalFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Conditional Field Alias";
        private const string RuleDescription = "The field alias: '{0}' maps to a property path that only exists in the resource type: '{1}' if some conditions are met. In all other cases, the property might be missing. Affected API versions: '{2}'";

        /// <summary>
        /// Initializes a new instance of the <see cref="ConditionalFieldAlias"/> class.
        /// </summary>
        public ConditionalFieldAlias() : base(
            identifier: "conditional-field-alias",
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
                var conditionalMetadata = expression.ResourcePropertyMetadata
                    .Where(metadata => metadata.Exists && metadata.IsConditional)
                    .ToArray();

                var conditionalApiVersions = conditionalMetadata
                    .SelectMany(metadata => metadata.ApiVersions)
                    .Distinct()
                    .OrderBy(v => v, comparer: SuffixAwareApiVersionComparer.Instance)
                    .ToArray();

                if (conditionalApiVersions.Length != 0)
                {
                    var resourceType = conditionalMetadata[0].ResourceType;
                    var apiVersionsFormatted = string.Join(", ", conditionalApiVersions);

                    return new[] { this.CreateWarning(expression, expression.Identifier, resourceType, apiVersionsFormatted) };
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
