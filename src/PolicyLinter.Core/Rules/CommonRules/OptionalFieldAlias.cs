// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers;

    /// <summary>
    /// Detects field aliases that map to properties marked as optional in some API versions of the resource type.
    /// </summary>
    public sealed class OptionalFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Optional Field Alias";
        private const string RuleDescription = "The field alias: '{0}' maps to property path that marked as optional in some API version of resource type: '{1}' . API versions: '{2}'";

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
                        .Where(metadata => metadata.Exists && !metadata.IsRequired)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Distinct()
                        .OrderBy(v => v, comparer: SuffixAwareApiVersionComparer.Instance)
                        .ToArray();

                    if (readonlyApiVersions.Length != 0)
                    {
                        var resourceType = expression.ResourcePropertyMetadata.First().ResourceType;
                        var apiVersionsFormatted = string.Join(", ", readonlyApiVersions);
                        return new[] { this.CreateWarning(expression, expression.Identifier, resourceType, apiVersionsFormatted) };
                    }
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
