// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;

    /// <summary>
    /// Flags scalar comparisons that use field() for a counted array alias inside count.where.
    /// </summary>
    public sealed class FieldFunctionOnCountedArrayAlias : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Field Function on Counted Array Alias";
        private const string RuleDescription =
            "The field() function on the counted alias '{0}' returns a one-member array inside count.where, while current('{0}') returns the current scalar value. Use current('{0}') for this scalar comparison.";

        private static readonly OrdinalInsensitiveHashSet ScalarComparisonOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
            "like",
            "notLike",
            "match",
            "notMatch",
            "matchInsensitively",
            "notMatchInsensitively",
            "greater",
            "greaterOrEquals",
            "less",
            "lessOrEquals",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldFunctionOnCountedArrayAlias"/> class.
        /// </summary>
        public FieldFunctionOnCountedArrayAlias() : base(
            identifier: "field-function-on-counted-array-alias",
            category: Category.BestPractices,
            title: FieldFunctionOnCountedArrayAlias.RuleTitle,
            descriptionFormat: FieldFunctionOnCountedArrayAlias.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Value == null ||
                expression.Operator == null ||
                !FieldFunctionOnCountedArrayAlias.ScalarComparisonOperators.Contains(expression.Operator.Name) ||
                expression.Value.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var languageExpression = expression.Value.LanguageExpressions[0];
            if (!string.Equals(languageExpression.Expression, expression.Value.Value.ToString(), StringComparison.Ordinal) ||
                languageExpression.ReferenceKind != ReferenceKind.ResourceField ||
                languageExpression.References.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var reference = languageExpression.References[0];
            if (!reference.IsResolved || reference.ReferencedCountExpressionScope == null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Value, reference.Identifier),
            };
        }
    }
}
