// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Linq;

    /// <summary>
    /// Detects field aliases whose resolved property path is nested more than two resource bodies deep, which often
    /// indicates the alias threads through a referenced resource and points at a property that does not exist on the evaluated resource.
    /// </summary>
    public sealed class DeeplyNestedFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Deeply Nested Field Alias";
        private const string RuleDescription = "The field alias: '{0}' resolves to a property path nested {1} levels deep. Deeply nested paths often cross into a referenced resource, so the targeted property may not exist on the evaluated resource. Verify it against the resource provider's REST API documentation.";

        /// <summary>
        /// The maximum property nesting depth that is treated as a legitimately embedded child resource.
        /// </summary>
        private const int MaxEmbeddedNestingDepth = 2;

        /// <summary>
        /// Initializes a new instance of the <see cref="DeeplyNestedFieldAlias"/> class.
        /// </summary>
        public DeeplyNestedFieldAlias() : base(
            identifier: "deeply-nested-field-alias",
            category: Category.ResourceFields,
            title: RuleTitle,
            descriptionFormat: RuleDescription,
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

            var defaultPath = expression.ResourcePropertyMetadata.FirstOrDefault()?.Alias?.DefaultPath;
            if (string.IsNullOrEmpty(defaultPath))
            {
                return Array.Empty<LinterOutput>();
            }

            var nestingDepth = defaultPath
                .Split('.')
                .Count(segment => segment.Equals("properties", StringComparison.OrdinalIgnoreCase));

            if (nestingDepth <= DeeplyNestedFieldAlias.MaxEmbeddedNestingDepth)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateWarning(expression, expression.Identifier, nestingDepth) };
        }
    }
}
