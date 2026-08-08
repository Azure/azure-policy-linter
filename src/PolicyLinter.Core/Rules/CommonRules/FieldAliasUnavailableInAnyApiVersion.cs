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
    /// Detects field aliases for which the embedded metadata has no property path in any known API version.
    /// </summary>
    public sealed class FieldAliasUnavailableInAnyApiVersion : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Alias Unavailable in Any API Version";
        private const string RuleDescription =
            "The field alias '{0}' maps to an unknown property on resource type '{1}', according to the linter's embedded metadata. Verify that the property exists on the target resource.";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasUnavailableInAnyApiVersion"/> class.
        /// </summary>
        public FieldAliasUnavailableInAnyApiVersion() : base(
            identifier: "field-alias-unavailable-in-any-api-version",
            category: Category.ResourceFields,
            title: FieldAliasUnavailableInAnyApiVersion.RuleTitle,
            descriptionFormat: FieldAliasUnavailableInAnyApiVersion.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (!expression.IsResolvedFieldReference() ||
                !FieldPathHelper.IsFieldAlias(expression.Identifier) ||
                !FieldPathHelper.FieldAliasHasFullyQualifiedResourceType(expression.Identifier))
            {
                return Array.Empty<LinterOutput>();
            }

            if (expression.ResourcePropertyMetadata.Any(metadata => metadata.Exists))
            {
                return Array.Empty<LinterOutput>();
            }

            var resourceType = FieldPathHelper.GetFieldAliasFullyQualifiedResourceType(expression.Identifier);

            return new[]
            {
                this.CreateError(expression, expression.Identifier, resourceType)
            };
        }
    }
}
