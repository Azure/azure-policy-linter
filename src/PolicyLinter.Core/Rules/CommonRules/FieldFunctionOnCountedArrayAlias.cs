// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
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
            if (expression.Operator == null ||
                !FieldFunctionOnCountedArrayAlias.ScalarComparisonOperators.Contains(expression.Operator.Name))
            {
                return Array.Empty<LinterOutput>();
            }

            var outputs = new List<LinterOutput>();
            foreach (var property in new[] { expression.Value, expression.Operator })
            {
                var reference = FieldFunctionOnCountedArrayAlias.GetCountedArrayFieldReference(property);
                if (reference != null)
                {
                    outputs.Add(this.CreateWarning(property, reference.Identifier));
                }
            }

            return outputs.ToArray();
        }

        private static Reference? GetCountedArrayFieldReference(Property? property)
        {
            if (property == null || property.LanguageExpressions.Length != 1)
            {
                return null;
            }

            var languageExpression = property.LanguageExpressions[0];
            if (!string.Equals(languageExpression.Expression, property.Value.ToString(), StringComparison.Ordinal) ||
                languageExpression.ReferenceKind != ReferenceKind.ResourceField ||
                languageExpression.References.Length != 1)
            {
                return null;
            }

            var reference = languageExpression.References[0];
            return reference.IsResolved && reference.ReferencedCountExpressionScope != null
                ? reference
                : null;
        }
    }
}
