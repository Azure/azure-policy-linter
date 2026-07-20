// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Identifies field conditions that implicitly enumerate an array alias.
    /// </summary>
    public sealed class ImplicitArrayEnumeration : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Implicit Array Enumeration";

        private const string RuleDescription =
            "The field alias '{0}' selects array members. Azure Policy applies the condition to every value selected by the array alias, and an empty collection satisfies it. Use field count when you need explicit member or empty-array handling.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ImplicitArrayEnumeration"/> class.
        /// </summary>
        public ImplicitArrayEnumeration() : base(
            identifier: "implicit-array-enumeration",
            category: Category.BestPractices,
            title: ImplicitArrayEnumeration.RuleTitle,
            descriptionFormat: ImplicitArrayEnumeration.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var reference = expression.Field?.FieldAccessorReference;

            if (reference?.IsResolved != true ||
                !FieldPathHelper.IsArrayAlias(reference.Identifier) ||
                expression.Operator == null ||
                string.Equals(expression.Operator.Name, "exists", StringComparison.OrdinalIgnoreCase) ||
                reference.ReferencedCountExpressionScope != null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression.Field, reference.Identifier),
            };
        }
    }
}
