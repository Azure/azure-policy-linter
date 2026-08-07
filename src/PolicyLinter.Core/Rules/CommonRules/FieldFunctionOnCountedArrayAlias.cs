// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Flags scalar comparisons that use field() for a counted array alias inside count.where.
    /// </summary>
    public sealed class FieldFunctionOnCountedArrayAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Field Function on Counted Array Alias";
        private const string RuleDescription =
            "The where condition uses field('{0}') on the counted alias, which has unintuitive behavior. Use current('{0}') to read the field of the array member being counted.";

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
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.Kind != ReferenceKind.ResourceField ||
                !expression.IsResolvedFieldReference() ||
                expression.ReferencedCountExpressionScope == null ||
                expression.Parent is not TemplateLanguageExpression)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression, expression.Identifier)
            };
        }
    }
}
