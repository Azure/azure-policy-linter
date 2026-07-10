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
    /// Detects field aliases that map to properties that are not marked as required in some API versions of the resource type.
    /// </summary>
    public sealed class OptionalFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Optional Field Alias";
        private const string RuleDescription = "The field alias: '{0}' maps to a property that is not marked as required in some API versions of resource type: '{1}'. API versions: '{2}'";

        /// <summary>
        /// Initializes a new instance of the <see cref="OptionalFieldAlias"/> class.
        /// </summary>
        public OptionalFieldAlias() : base(
            identifier: "optional-field-alias",
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
                    var readonlyApiVersions = expression.ResourcePropertyMetadata
                        .Where(metadata => metadata.Exists && !metadata.IsRequired && !metadata.IsConditional && !metadata.IsReadonly)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Distinct()
                        .OrderBy(v => v, comparer: SuffixAwareApiVersionComparer.Instance)
                        .ToArray();

                    if (readonlyApiVersions.Length != 0)
                    {
                        var resourceType = expression.ResourcePropertyMetadata.First().ResourceType;
                        var apiVersionsFormatted = string.Join(", ", readonlyApiVersions);
                        return new[] { this.CreateInformational(expression, expression.Identifier, resourceType, apiVersionsFormatted) };
                    }
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
