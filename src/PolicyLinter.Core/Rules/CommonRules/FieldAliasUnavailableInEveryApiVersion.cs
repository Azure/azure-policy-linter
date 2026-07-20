// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects field aliases for which the offline metadata has no property path in any known API version.
    /// </summary>
    public sealed class FieldAliasUnavailableInEveryApiVersion : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Alias Unavailable in Every API Version";
        private const string RuleDescription =
            "The field alias '{0}' resolves to resource type '{1}', but the linter's offline metadata contains no matching property path in any known API version. " +
            "Verify that the property exists on the target resource.";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasUnavailableInEveryApiVersion"/> class.
        /// </summary>
        public FieldAliasUnavailableInEveryApiVersion() : base(
            identifier: "field-alias-unavailable-in-every-api-version",
            category: Category.ResourceFields,
            title: FieldAliasUnavailableInEveryApiVersion.RuleTitle,
            descriptionFormat: FieldAliasUnavailableInEveryApiVersion.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (!expression.IsResolvedFieldReference() || !FieldPathHelper.IsFieldAlias(expression.Identifier))
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.ResourcePropertyMetadata.Any() ||
                expression.ResourcePropertyMetadata.Any(metadata => metadata.Exists))
            {
                return Array.Empty<LinterOutput>();
            }

            var resourceType = expression.ResourcePropertyMetadata
                .Select(metadata => metadata.ResourceType)
                .Where(resourceType => !string.IsNullOrWhiteSpace(resourceType))
                .OrderBy(resourceType => resourceType, comparer: StringComparer.OrdinalIgnoreCase)
                .ThenBy(resourceType => resourceType, comparer: StringComparer.Ordinal)
                .FirstOrDefault();

            if (resourceType == null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression, expression.Identifier, resourceType),
            };
        }
    }
}
